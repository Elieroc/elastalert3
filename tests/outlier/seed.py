"""Writes an outlier scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
The 24 hours before END (2026-10-12T12:00Z), bytes_out per user.name, 4 documents each:
  u00..u11  about 100 bytes in total (100..111)  -> the peers, median 106
  mallory   5000 bytes in total                  -> 47x the median
  old       9999999 bytes, but 3 days before END -> out of the timeframe, must not count
Run, from tests/outlier (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-12T11:00:00Z --end 2026-10-12T12:05:00Z
Expected matches: outlier.yaml: mallory (ratio 47.17); small_population.yaml: none (13 entities < 50);
p99.yaml: mallory (0.9 x the p99 of the population).
Second index outlier-peers, for peer_field (same 24 hours, 1 document per user):
  admin dept: adm00..adm11 about 5000 bytes (5000..5011), and evil 90000 -> 13 admins, median 5006
  acct dept:  acc00..acc13 about 100 bytes (100..113)                   -> 14 accountants
  temp dept:  t0, t1, t2 (10, 10, 99999)                                -> 3 users < min_population 10, skipped
  no dept:    nodept 99999                                              -> in no group, never judged
peer.yaml (peer_field: user.dept): evil only, 17.98x the median 5006 of its group (13 entities).
nopeer.yaml (same rule without peer_field): the 13 admins and temp/nodept users above 10x the median of the 31 users (113)."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es = sys.argv[1].rstrip('/')
end = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/logs-outlier', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'user': {'properties': {'name': {'type': 'keyword'}}}, 'bytes_out': {'type': 'long'}}}}).encode())
totals = {f'u{i:02}': 100 + i for i in range(12)} | {'mallory': 5000}
docs = []
for user, total in totals.items():
    for part in range(4):
        docs.append((user, total // 4 + (total % 4 if part == 0 else 0), end - timedelta(hours=2 + 5 * part)))
docs.append(('old', 9999999, end - timedelta(days=3)))
body = ''.join(json.dumps({'index': {'_index': 'logs-outlier'}}) + '\n' + json.dumps({'@timestamp': t.isoformat(timespec='seconds').replace('+00:00', 'Z'), 'user': {'name': u}, 'bytes_out': b}) + '\n' for u, b, t in docs)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(docs))

call('PUT', '/outlier-peers', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'user': {'properties': {'name': {'type': 'keyword'}, 'dept': {'type': 'keyword'}}}, 'bytes_out': {'type': 'long'}}}}).encode())
people = [(f'adm{i:02}', 'admin', 5000 + i) for i in range(12)] + [('evil', 'admin', 90000)] \
    + [(f'acc{i:02}', 'acct', 100 + i) for i in range(14)] + [('t0', 'temp', 10), ('t1', 'temp', 10), ('t2', 'temp', 99999), ('nodept', None, 99999)]
body = ''.join(json.dumps({'index': {'_index': 'outlier-peers'}}) + '\n' + json.dumps({'@timestamp': (end - timedelta(hours=3)).isoformat(timespec='seconds').replace('+00:00', 'Z'), 'user': {'name': u} | ({'dept': d} if d else {}), 'bytes_out': b}) + '\n' for u, d, b in people)
print('peers errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(people))
