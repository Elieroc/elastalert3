"""Writes a risk_ratio scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200 [index]
Alert docs of other rules (rule_name + risk_objects) in a throwaway writeback index (default rtest_status), END = 2026-10-12T12:00Z:
  noisy: 70 every 70 min from END-9h (never 100 within an hour), then 60 (rule a) + 50 (rule b) at END-30min = 110, then 90 at END-10min.
  quiet: 60 (rule a) + 50 (rule b) at END-20min = 110, nothing before.
Run, from tests/risk_ratio (throwaway ES, see tests/rare/seed.py; the config reads ES_HOST / ES_PORT):
  elastalert --config config.yaml --debug --start 2026-10-12T00:50:00Z --end 2026-10-12T12:05:00Z
Expected matches: rules/ratio.yaml: noisy at 200 (usual 49.0 per hour, ratio 3) and quiet at 110 (usual 0).
  rules/fixed.yaml (no ratio): noisy at 110 (END-30min) and quiet at 110."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, index = sys.argv[1].rstrip('/'), (sys.argv[2] if len(sys.argv) > 2 else 'rtest_status')
end = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/' + index, json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'rule_name': {'type': 'keyword'}, 'risk_objects': {'properties': {'type': {'type': 'keyword'}, 'value': {'type': 'keyword'}, 'score': {'type': 'float'}}}}}}).encode())
alerts = [('a', end - timedelta(hours=9) + timedelta(minutes=70 * i), 'noisy', 70) for i in range(7)]
alerts += [('a', end - timedelta(minutes=30), 'noisy', 60), ('b', end - timedelta(minutes=30) + timedelta(seconds=5), 'noisy', 50), ('c', end - timedelta(minutes=10), 'noisy', 90),
           ('a', end - timedelta(minutes=20), 'quiet', 60), ('b', end - timedelta(minutes=20) + timedelta(seconds=5), 'quiet', 50)]
iso = lambda t: t.isoformat(timespec='seconds').replace('+00:00', 'Z')
body = ''.join(json.dumps({'index': {'_index': index}}) + '\n' + json.dumps({'@timestamp': iso(t), 'rule_name': r, 'risk_objects': [{'type': 'host', 'value': h, 'score': s}]}) + '\n' for r, t, h, s in alerts)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(alerts))
