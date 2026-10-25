"""Runs the Sigma rules of tests/sigma/rules against a throwaway Elasticsearch and checks which events each one hits.
The expected hits (expected.json) were derived by hand from the events below, so a difference is a bug in the query or
in the expectation, never "whatever the code does".

Usage: python3 run.py http://127.0.0.1:19200 [path/to/elastalert]

With pySigma installed (`sigma` command, pysigma-backend-elasticsearch) every rule is also converted by
`sigma convert -t lucene --without-pipeline` and run on a second index whose keyword fields lowercase, and both id sets
must be equal."""
import json, os, shutil, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
es = sys.argv[1].rstrip('/')
binary = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, '..', '..', 'target', 'debug', 'elastalert')

W = 'C:\\Windows\\System32\\'
PS = W + 'WindowsPowerShell\\v1.0\\powershell.exe'
EVENTS = {
    'e1': {'EventID': 1, 'Image': W + 'cmd.exe', 'CommandLine': 'cmd.exe /c whoami', 'User': 'alice'},
    'e2': {'EventID': 1, 'Image': W + 'CMD.EXE', 'CommandLine': 'cmd /c ECHO hi', 'User': 'SYSTEM'},
    'e3': {'EventID': 1, 'Image': PS, 'CommandLine': 'powershell -enc SQBFAFgA', 'User': 'bob'},
    'e4': {'EventID': 1, 'Image': PS, 'CommandLine': 'powershell /ENC SQBFAFgA', 'User': 'SYSTEM'},
    'e5': {'EventID': 1, 'Image': PS, 'CommandLine': 'powershell \u2013enc abc', 'User': 'carol'},
    'e6': {'EventID': 1, 'Image': 'C:\\Tools\\notepad.exe', 'CommandLine': 'notepad.exe C:\\a.txt'},
    'e7': {'EventID': 1, 'Image': W + 'net.exe', 'CommandLine': 'net user admin /add', 'User': 'alice', 'ParentImage': W + 'cmd.exe'},
    'e8': {'EventID': 3, 'Image': PS, 'DestinationIp': '10.1.2.3', 'DestinationPort': 4444},
    'e9': {'EventID': 3, 'Image': 'C:\\Program Files\\app.exe', 'DestinationIp': '192.168.1.5', 'DestinationPort': 80},
    'e10': {'EventID': 3, 'Image': 'C:\\Program Files\\app.exe', 'DestinationIp': '8.8.8.8', 'DestinationPort': 443},
    'e11': {'EventID': 1, 'Image': PS, 'CommandLine': 'powershell -e dwBoAG8AYQBtAGkA'},
    'e12': {'message': 'Failed password for root from 1.2.3.4'},
    'e13': {'EventID': 1, 'Image': 'C:\\x\\evil.exe', 'CommandLine': 'evil 12345'},
    'e14': {'EventID': 1, 'Image': 'C:\\z.exe', 'CommandLine': 'echo a*b'},
    'e15': {'EventID': 1, 'Image': 'C:\\z.exe', 'CommandLine': 'echo axb'},
    'e16': {'EventID': 1, 'Image': 'C:\\z.exe', 'CommandLine': 'ping 10.0.0.5 -n 3'},
}


def call(method, path, body=None, ndjson=False):
    data = None if body is None else (body if ndjson else json.dumps(body)).encode()
    req = urllib.request.Request(es + path, data=data, method=method,
                                 headers={'Content-Type': 'application/x-ndjson' if ndjson else 'application/json'})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {'error': e.read().decode(), 'status': e.code}


def load(index, lowercase):
    call('DELETE', '/' + index)
    keyword = {'type': 'keyword'}
    if lowercase:
        keyword['normalizer'] = 'lc'
    settings = {'analysis': {'normalizer': {'lc': {'type': 'custom', 'filter': ['lowercase']}}}}
    r = call('PUT', '/' + index, {
        'settings': settings,
        'mappings': {'dynamic_templates': [{'strings': {'match_mapping_type': 'string', 'mapping': keyword}}],
                     'properties': {'DestinationIp': {'type': 'ip'}}}})
    assert 'error' not in r, r
    lines = []
    for i, doc in EVENTS.items():
        lines += [json.dumps({'index': {'_index': index, '_id': i}}), json.dumps(doc)]
    r = call('POST', '/_bulk?refresh=true', '\n'.join(lines) + '\n', ndjson=True)
    assert not r['errors'], r


def ids(index, query):
    r = call('POST', f'/{index}/_search', {'query': query, 'size': 100, '_source': False})
    if 'error' in r:
        raise SystemExit(f'search failed: {r["error"]}')
    return sorted(h['_id'] for h in r['hits']['hits'])


def ours(rule):
    out = subprocess.run([binary, 'sigma-convert', '--dsl', '--keyword-field', 'message', rule], capture_output=True, text=True)
    if out.returncode:
        raise SystemExit(f'{rule}: {out.stderr.strip()}')
    return json.loads(out.stdout)['query']


load('sigma-parity', lowercase=False)
expected = json.load(open(os.path.join(HERE, 'expected.json')))
rules = sorted(f for f in os.listdir(os.path.join(HERE, 'rules')) if f.endswith('.yml'))
failed = 0
for f in rules:
    name = f[:-4]
    got = ids('sigma-parity', ours(os.path.join(HERE, 'rules', f)))
    ok = got == expected.get(name)
    failed += not ok
    print(f'{"ok  " if ok else "FAIL"} {name}: {got}' + ('' if ok else f' (expected {expected.get(name)})'))
for name in sorted(set(expected) - {f[:-4] for f in rules}):
    failed += 1
    print(f'FAIL {name}: no rule file')

if shutil.which('sigma'):
    # Lowercasing keyword fields makes Lucene's case-sensitive query_string behave like Sigma's case-insensitive match.
    load('sigma-parity-lc', lowercase=True)
    for f in rules:
        name = f[:-4]
        if name == 'cased':
            continue  # needs case-sensitive fields
        path = os.path.join(HERE, 'rules', f)
        conv = subprocess.run(['sigma', 'convert', '-t', 'lucene', '--without-pipeline', path], capture_output=True, text=True)
        if conv.returncode:
            print(f'skip {name} (pySigma: {conv.stderr.strip().splitlines()[-1] if conv.stderr.strip() else "error"})')
            continue
        theirs = ids('sigma-parity-lc', {'query_string': {'query': conv.stdout.strip(), 'analyze_wildcard': False}})
        mine = ids('sigma-parity-lc', ours(path))
        ok = theirs == mine
        failed += not ok
        print(f'{"ok  " if ok else "FAIL"} pySigma {name}: {mine}' + ('' if ok else f' != {theirs}'))
else:
    print('pySigma not installed: skipped the comparison with `sigma convert -t lucene`')

sys.exit(1 if failed else 0)
