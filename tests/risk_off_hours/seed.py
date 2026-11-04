"""Writes a risk off_hours_bonus scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200 [index]
Alert docs of one rule (3 x 30 = 90 per host, under risk_threshold 100) in a throwaway writeback index (default rtest_oh_status).
2026-10-12 is a Monday; the usual hours of rules/bonus.yaml are Monday to Friday 08:00-19:00 UTC, bonus 10 per alert.
  night:   Mon 02:10, 02:20, 02:30 (outside the hours)
  day:     Mon 10:00, 10:10, 10:20 (inside)
  weekend: Sat 2026-10-10 14:00, 14:10, 14:20 (right time of day, wrong day)
Run, from tests/risk_off_hours (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-10T00:00:00Z --end 2026-10-12T12:05:00Z
Expected matches: rules/bonus.yaml: night and weekend at 120 (3 x 40), not day (90).
  rules/plain.yaml (no bonus): nothing (90 everywhere).
check.py runs the daemon and compares."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, index = sys.argv[1].rstrip('/'), (sys.argv[2] if len(sys.argv) > 2 else 'rtest_oh_status')
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
try:
    call('DELETE', '/' + index)
except Exception:
    pass
call('PUT', '/' + index, json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'rule_name': {'type': 'keyword'}, 'risk_objects': {'properties': {'type': {'type': 'keyword'}, 'value': {'type': 'keyword'}, 'score': {'type': 'float'}}}}}}).encode())
at = lambda d, h, m: datetime(2026, 10, d, h, m, tzinfo=timezone.utc)
alerts = [(host, at(d, h, m + 10 * i)) for host, d, h, m in [('night', 12, 2, 10), ('day', 12, 10, 0), ('weekend', 10, 14, 0)] for i in range(3)]
iso = lambda t: t.isoformat(timespec='seconds').replace('+00:00', 'Z')
body = ''.join(json.dumps({'index': {'_index': index}}) + '\n' + json.dumps({'@timestamp': iso(t), 'rule_name': 'a', 'risk_objects': [{'type': 'host', 'value': h, 'score': 30}]}) + '\n' for h, t in alerts)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(alerts))
