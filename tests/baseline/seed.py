"""Writes a baseline scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200 [END]
Three weeks of hourly events before END (default Monday 2026-10-12T12:00Z, a whole hour; spikes are at END-2h, END-1h) (a few thousand documents):
  alice  12 +-1 an hour, always                                  -> never abnormal
  bob    10 +-1 an hour, 100 in the END-2h hour   -> spike
  carol  3 an hour, 60 every Monday 09:00 (this one included)    -> normal for hour_of_week, abnormal for none
  dave   10 +-1 an hour, none in the END-2h hour  -> drop to zero
  frank  10 +-1 an hour, 2000 in one past hour, 22 in the END-1h hour -> abnormal for mad, not for zscore
Run, from tests/baseline (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-12T07:00:00Z --end 2026-10-12T12:05:00Z
Expected matches (bucket start, rule):  bob 10:00 and dave 10:00 (baseline.yaml), carol 09:00 (carol_none.yaml),
frank 11:00 (frank_mad.yaml); none for frank_zscore.yaml."""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, rnd = sys.argv[1].rstrip('/'), random.Random(11)
end = datetime.fromisoformat(sys.argv[2].replace('Z', '+00:00')) if len(sys.argv) > 2 else datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/logs-baseline', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'user': {'type': 'keyword'}}}}).encode())
docs, outlier = [], end - timedelta(days=10, hours=5)
for i in range(21 * 24, 0, -1):
    h = end - timedelta(hours=i)
    n = {'alice': 12 + rnd.randint(-1, 1), 'bob': 10 + rnd.randint(-1, 1), 'carol': 3, 'dave': 10 + rnd.randint(-1, 1), 'frank': 10 + rnd.randint(-1, 1)}
    if h.weekday() == 0 and h.hour == 9: n['carol'] = 60
    if h == end - timedelta(hours=2): n['bob'], n['dave'] = 100, 0
    if h == outlier: n['frank'] = 2000
    if h == end - timedelta(hours=1): n['frank'] = 22
    for user, c in n.items():
        for _ in range(c):
            ts = h + timedelta(seconds=rnd.uniform(0, 3599.9))
            docs.append((user, ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z')))
body = ''.join(json.dumps({'index': {'_index': 'logs-baseline'}}) + '\n' + json.dumps({'@timestamp': t, 'user': u}) + '\n' for u, t in docs)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(docs))
