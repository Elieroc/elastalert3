"""Runs the omega-rules against test documents in a throwaway Elasticsearch (see omega-rules/README.md for the docker command).
Usage: python3 run.py ES_URL [--bin PATH] [rule-name ...]

tests/omega/cases/<rule-name>.yaml:
  docs:                          # @timestamp is filled in (one per second from 2026-01-01T10:00:00Z) when absent
  - {id: miner, match: true, doc: {process: {name: xmrig}, host: {name: h1}}}
  - {id: benign, doc: {process: {name: ls}}}
  start: / end:                  # optional ISO range of the replay (default: 1 h around 2026-01-01T10:00:00Z)
  ignored: N                     # optional: matches that active_hours must drop (counted in the log)
  matches: 1                     # optional: what the rule type produces (default for `any`/`blacklist`: the number of match: true docs)
`mappings:` (optional) adds ES field mappings; strings are keyword and `*.ip` fields are ip by default.
`match: true` docs must be returned by the rule's query and no other doc may be. `matches` is checked on the rule's matches."""
import datetime, json, os, subprocess, sys, tempfile, urllib.error, urllib.request
import yaml
import lib

args = sys.argv[1:]
bin_ = lib.binary(args[args.index('--bin') + 1] if '--bin' in args else None)
if '--bin' in args:
    del args[args.index('--bin'):args.index('--bin') + 2]
if not args:
    raise SystemExit(__doc__)
es, only = args[0].rstrip('/'), set(args[1:])
BASE = datetime.datetime(2026, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
iso = lambda t: t.strftime('%Y-%m-%dT%H:%M:%SZ')


def call(method, path, body=None, ndjson=False):
    data = None if body is None else (body if ndjson else json.dumps(body)).encode()
    req = urllib.request.Request(es + path, data=data, method=method,
                                 headers={'Content-Type': 'application/x-ndjson' if ndjson else 'application/json'})
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {'error': e.read().decode(), 'status': e.code}


rules = {os.path.basename(f).rsplit('.', 1)[0]: f for p in lib.PREFIX for f in lib.rule_files(os.path.join(lib.PACKS, p))}
cases = sorted(f[:-5] for f in os.listdir(lib.CASES) if f.endswith('.yaml')) if os.path.isdir(lib.CASES) else []
failed = ran = 0
with tempfile.TemporaryDirectory() as tmp:
    cfg = os.path.join(tmp, 'config.yaml')
    open(cfg, 'w').write(f'rules_folder: {tmp}\nes_host: {es.split("//")[1].split(":")[0]}\nes_port: {es.rsplit(":", 1)[1]}\n'
                         'writeback_index: omega_test\nrun_every: {minutes: 1}\nbuffer_time: {minutes: 15}\n')
    for name in cases:
        if only and name not in only:
            continue
        ran += 1
        if name not in rules:
            print(f'FAIL {name}: case without rule')
            failed += 1
            continue
        rule, _ = lib.load(rules[name])
        # A risk rule reads the writeback index (omega_test here): its docs are alert docs with risk_objects.
        pattern = rule.get('index', 'omega_test').split(',')[0].strip() if rule['type'] != 'risk' else 'omega_test'
        index = pattern[:-1] + '-omega' if pattern.endswith('*') else pattern
        case = yaml.safe_load(open(os.path.join(lib.CASES, name + '.yaml')))
        call('DELETE', f'/{index}')
        call('DELETE', '/omega_test*' if rule['type'] != 'risk' else '/omega_test_*')
        # Plain index (priority above the built-in logs-*-* data stream template), strings as keyword like Elastic's ECS mappings.
        mapping = {'dynamic_templates': [{'ips': {'path_match': '*.ip', 'mapping': {'type': 'ip'}}},
                                         {'strings': {'match_mapping_type': 'string', 'mapping': {'type': 'keyword'}}}],
                   'properties': {'@timestamp': {'type': 'date'}, **case.get('mappings', {})}}
        r = call('PUT', '/_index_template/omega-test', {'index_patterns': [index], 'priority': 500, 'template': {'mappings': mapping}})
        if 'error' in r:
            print(f'FAIL {name}: template {json.dumps(r)[:300]}')
            failed += 1
            continue
        lines, want, ids = [], set(), []
        # Legitimate activity of the rule's source: a T0 or T2 event rule must not hit any of it.
        benign = []
        src = (rule.get('omega') or {}).get('source', [''])[0]
        bpath = os.path.join(lib.HERE, 'benign', src + '.yaml')
        if rule['type'] == 'any' and os.path.exists(bpath):
            for i, b in enumerate(yaml.safe_load(open(bpath))):
                doc = lib.nest(lib.BENIGN_BASE[src])
                doc = lib.deep_merge(doc, lib.nest(b))
                doc['@timestamp'] = iso(BASE + datetime.timedelta(minutes=30, seconds=i))
                benign.append((f'benign{i+1}', doc))
                lines += [json.dumps({'index': {'_index': index, '_id': f'benign{i+1}'}}), json.dumps(doc)]
        for i, d in enumerate(case['docs']):
            doc = dict(d['doc'])
            doc.setdefault('@timestamp', iso(BASE + datetime.timedelta(seconds=i)))
            ids.append(d['id'])
            if d.get('match'):
                want.add(d['id'])
            lines += [json.dumps({'index': {'_index': index, '_id': d['id']}}), json.dumps(doc)]
        r = call('POST', '/_bulk?refresh=true', '\n'.join(lines) + '\n', ndjson=True)
        if r.get('errors') or 'error' in r:
            print(f'FAIL {name}: indexing {json.dumps(r)[:300]}')
            failed += 1
            continue
        out = subprocess.run([bin_, '--config', cfg, 'test-rule', rules[name], '--start', case.get('start', iso(BASE - datetime.timedelta(hours=1))),
                              '--end', case.get('end', iso(BASE + datetime.timedelta(hours=1))), '--formatted-output'],
                             capture_output=True, text=True)
        js = [l for l in out.stdout.splitlines() if l.startswith('{') and l.rstrip().endswith('}')]
        if out.returncode or not js:
            print(f'FAIL {name}: test-rule: {(out.stderr or out.stdout).strip()[-400:]}')
            failed += 1
            continue
        res = json.loads(js[-1])
        hit = {h['_id'] for h in res.get('results', [])}
        benign_hit = sorted(h for h in hit if h.startswith('benign'))
        hit -= set(benign_hit)
        note = ''
        problems = [f'log: {l.strip()[:300]}' for l in out.stderr.splitlines() if 'ERROR' in l or 'rror:' in l][:2]
        if hit != want:
            problems.append(f'query hit {sorted(hit)}, expected {sorted(want)}')
        status = next((v for k, v in res.get('writeback', {}).items() if k.endswith('_status')), {})
        expect = case.get('matches', len(want) if rule['type'] in ('any', 'blacklist') else None)
        if benign_hit and rule['type'] in ('any', 'blacklist') and (rule.get('omega') or {}).get('tier') == 'T1' and expect is not None:
            expect += len(benign_hit)
        if expect is not None and status.get('matches') != expect:
            problems.append(f'{status.get("matches")} match(es), expected {expect}')
        if 'ignored' in case:
            ignored = sum(1 for l in out.stderr.splitlines() if 'outside active_hours' in l)
            # the benign documents are dated a Thursday at 10:30 UTC, in working hours: an off-hours rule drops them all
            want_ignored = case['ignored'] + len(benign_hit)
            if ignored != want_ignored:
                problems.append(f'{ignored} match(es) ignored by active_hours, expected {want_ignored}')
        if benign_hit and (rule.get('omega') or {}).get('tier') != 'T1':
            problems.append(f'hit legitimate activity: {benign_hit}')
        elif benign_hit:
            note = f' (signal hits {len(benign_hit)} benign doc(s))'
        failed += bool(problems)
        print(f'{"FAIL" if problems else "ok  "} {name}{note}' + ''.join(f'\n     {p}' for p in problems))
        call('DELETE', f'/{index}')
print(f'{ran} case(s), {failed} failed')
sys.exit(1 if failed else 0)
