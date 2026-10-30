"""Writes a log_loss scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200 [END]
Four weeks of hourly events before END (default Tuesday 2026-10-13T12:00Z, a whole hour), organisation acme:
  always  an event every hour, but none in the last 4 hours of the run  -> lost (normally silent at most 1 h)
  office  Monday-Friday 08:00-17:59 only, so silent 62 h every weekend  -> not lost (active on Tuesday noon)
  gone    like office, but nothing after END-42h (its last event is Friday 17:59) -> lost on Tuesday (91 h silent, 1 h is normal)
  fine    an event every hour, up to END                                 -> never lost
and organisation beta (3 sources: x, y, z): all three stop 5 hours before END -> mass loss for beta.
Run, from tests/log_loss (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node
-e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml --debug --start 2026-10-13T12:00:00Z --end 2026-10-13T12:05:00Z
Expected matches: acme/always, acme/gone, beta/x, beta/y, beta/z and one mass loss for beta (3 of 3; acme is 2 of 4, under mass_loss_ratio 0.75); not acme/office, not acme/fine."""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, rnd = sys.argv[1].rstrip('/'), random.Random(5)
end = datetime.fromisoformat(sys.argv[2].replace('Z', '+00:00')) if len(sys.argv) > 2 else datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/ll-events', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'org': {'type': 'keyword'}, 'src': {'type': 'keyword'}}}}).encode())
def office(h): return h.weekday() < 5 and 8 <= h.hour < 18
docs = []
for i in range(4 * 7 * 24, 0, -1):
    h = end - timedelta(hours=i)
    left = end - h
    srcs = []
    if left > timedelta(hours=4): srcs.append(('acme', 'always'))
    if office(h): srcs.append(('acme', 'office'))
    if office(h) and left > timedelta(hours=42): srcs.append(('acme', 'gone'))
    srcs.append(('acme', 'fine'))
    if left > timedelta(hours=5): srcs += [('beta', s) for s in 'xyz']
    for org, src in srcs:
        for _ in range(rnd.randint(1, 3)):
            ts = h + timedelta(seconds=rnd.uniform(0, 3599.9))
            docs.append((org, src, ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z')))
body = ''.join(json.dumps({'index': {'_index': 'll-events'}}) + '\n' + json.dumps({'@timestamp': t, 'org': o, 'src': s}) + '\n' for o, s, t in docs)
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(docs))
