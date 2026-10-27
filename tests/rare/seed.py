"""Writes a rare (new_term max_occurrences) scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
History (END-10d .. END-2d, END = 2026-10-12T12:00Z): common 10 times, rare 2 times, once 1 time, edge 3 times (limit), over 4 times.
Live window (END-1h .. END): every one of those terms, plus brandnew.
Run, from tests/rare (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-12T11:00:00Z --end 2026-10-12T12:05:00Z
Expected matches: plain.yaml: brandnew. rare.yaml and rare_terms_query.yaml: rare, once, edge, brandnew (not common, not over)."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es = sys.argv[1].rstrip('/')
end = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/logs-rare', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'process': {'properties': {'name': {'type': 'keyword'}}}}}}).encode())
hist = {'common': 10, 'rare': 2, 'once': 1, 'edge': 3, 'over': 4}
docs = [(n, end - timedelta(days=10, hours=i)) for n, c in hist.items() for i in range(c)]
docs += [(n, end - timedelta(minutes=50 - 5 * i)) for i, n in enumerate([*hist, 'brandnew'])]
body = ''.join(json.dumps({'index': {'_index': 'logs-rare'}}) + '\n' + json.dumps({'@timestamp': t.isoformat(timespec='seconds').replace('+00:00', 'Z'), 'process': {'name': n}}) + '\n' for n, t in docs)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(docs))
