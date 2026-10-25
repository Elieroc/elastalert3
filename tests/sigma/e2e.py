"""Runs the daemon over Sigma correlation rules and filters in `sigma_folders` against a throwaway Elasticsearch, and
checks which keys alert. Replays 2026-10-01 09:00-10:00 UTC with --debug, so nothing is sent.

Usage: python3 e2e.py http://127.0.0.1:19200 [path/to/elastalert]

Data: `alice` fails 11 times then succeeds, `bob` fails 3 times then succeeds, `svc_x` (named by the filter) fails 12
times then succeeds, `carol` succeeds and then fails 12 times."""
import json, os, re, subprocess, sys, tempfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
es = sys.argv[1].rstrip('/')
binary = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, '..', '..', 'target', 'debug', 'elastalert'))
INDEX = 'sigma-e2e'

# rule name -> keys that must alert
EXPECTED = {
    'mr_brute_force': ['alice'],                     # temporal_ordered of an event_count leaf and a detection, filter on svc_
    'mr_many_failed': ['alice', 'carol', 'svc_x'],  # event_count, gte 10
}


def call(method, path, body=None, ndjson=False):
    data = None if body is None else (body if ndjson else json.dumps(body)).encode()
    req = urllib.request.Request(es + path, data=data, method=method, headers={'Content-Type': 'application/x-ndjson' if ndjson else 'application/json'})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {'error': e.read().decode(), 'status': e.code}


def events():
    def doc(i, ts, user, eid):
        return [json.dumps({'index': {'_index': INDEX, '_id': i}}), json.dumps({'@timestamp': ts, 'User': user, 'EventID': eid})]
    out = []
    for k in range(11):
        out += doc(f'a{k}', f'2026-10-01T09:00:{k:02d}Z', 'alice', 4625)
    out += doc('a_ok', '2026-10-01T09:02:00Z', 'alice', 4624)
    for k in range(3):
        out += doc(f'b{k}', f'2026-10-01T09:00:{k:02d}Z', 'bob', 4625)
    out += doc('b_ok', '2026-10-01T09:02:00Z', 'bob', 4624)
    for k in range(12):
        out += doc(f's{k}', f'2026-10-01T09:00:{k:02d}Z', 'svc_x', 4625)
    out += doc('s_ok', '2026-10-01T09:02:00Z', 'svc_x', 4624)
    out += doc('c_ok', '2026-10-01T09:00:00Z', 'carol', 4624)
    for k in range(12):
        out += doc(f'c{k}', f'2026-10-01T09:01:{k:02d}Z', 'carol', 4625)
    return out


call('DELETE', '/' + INDEX)
r = call('POST', '/_bulk?refresh=true', '\n'.join(events()) + '\n', ndjson=True)
assert not r.get('errors', True), r

with tempfile.TemporaryDirectory() as tmp:
    sigma = os.path.join(tmp, 'sigma')
    os.makedirs(sigma)
    for f in os.listdir(os.path.join(HERE, 'e2e')):
        with open(os.path.join(HERE, 'e2e', f)) as src, open(os.path.join(sigma, f), 'w') as dst:
            dst.write(src.read())
    conf = os.path.join(tmp, 'config.yaml')
    host, port = re.match(r'https?://([^:/]+):(\d+)', es).groups()
    with open(conf, 'w') as c:
        c.write(f'''rules_folder: {tmp}/none
sigma_folders: [{sigma}]
sigma_defaults: {{alert: [debug], index: {INDEX}, realert: {{minutes: 0}}}}
es_host: {host}
es_port: {port}
writeback_index: sigma_e2e_status
run_every: {{minutes: 1}}
buffer_time: {{minutes: 15}}
alert_time_limit: {{days: 2}}
''')
    valid = subprocess.run([binary, '--config', conf, 'validate'], capture_output=True, text=True)
    print(valid.stdout.strip() or valid.stderr.strip())
    run = subprocess.run([binary, '--config', conf, '--debug', '--start', '2026-10-01T08:00:00Z', '--end', '2026-10-01T10:00:00Z'], capture_output=True, text=True)

alerts = {}
for m in re.finditer(r'^INFO:elastalert:Alert for (\S+), (\S+) at ', run.stderr, re.M):
    alerts.setdefault(m.group(1), set()).add(m.group(2))
failed = 0
for rule in sorted(set(EXPECTED) | set(alerts)):
    got, want = sorted(alerts.get(rule, [])), EXPECTED.get(rule)
    ok = got == want
    failed += not ok
    print(f'{"ok  " if ok else "FAIL"} {rule}: {got}' + ('' if ok else f' (expected {want})'))
if failed:
    print(run.stderr[-2000:])
sys.exit(1 if failed else 0)
