"""Writes an outlier scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
The 24 hours before END (2026-10-12T12:00Z), bytes_out per user.name, 4 documents each:
  u00..u11  about 100 bytes in total (100..111)  -> the peers, median 106
  mallory   5000 bytes in total                  -> 47x the median
  old       9999999 bytes, but 3 days before END -> out of the timeframe, must not count
Run, from tests/outlier (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-12T11:00:00Z --end 2026-10-12T12:05:00Z
Expected matches: outlier.yaml: mallory (ratio 47.17); small_population.yaml: none (13 entities < 50);
p99.yaml: mallory (0.9 x the p99 of the population)."""
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
