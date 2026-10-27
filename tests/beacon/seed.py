"""Writes a beacon scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
Window 2026-10-01T08:00Z..10:00Z, key = source.ip + destination.ip:
  10.0.0.1 -> 8.8.8.8   every 60 s with +-3 s jitter, 40 events    -> beacon
  10.0.0.2 -> 1.1.1.1   irregular times, 40 events                  -> no
  10.0.0.3 -> 9.9.9.9   every 2 s, 100 events                       -> no (min_interval)
  10.0.0.4 -> 8.8.8.8   every 60 s but only 5 events                -> no (min_events)
Run (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node -e xpack.security.enabled=false
docker.elastic.co/elasticsearch/elasticsearch:8.15.3), from tests/beacon:
  elastalert --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z
Expected: only 10.0.0.1 -> 8.8.8.8 matches, 2 matches (40 events, min_events 20)."""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, rnd = sys.argv[1].rstrip('/'), random.Random(7)
t0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
def ev(src, dst, secs):
    ts = t0 + timedelta(seconds=secs)
    return {'@timestamp': ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z'), 'source': {'ip': src}, 'destination': {'ip': dst}}
docs = [ev('10.0.0.1', '8.8.8.8', 60 * i + rnd.uniform(-3, 3) + 100) for i in range(40)]
docs += [ev('10.0.0.2', '1.1.1.1', t) for t in sorted(rnd.uniform(0, 3000) for _ in range(40))]
docs += [ev('10.0.0.3', '9.9.9.9', 2 * i) for i in range(100)]
docs += [ev('10.0.0.4', '8.8.8.8', 60 * i) for i in range(5)]
body = ''.join(json.dumps({'index': {'_index': 'logs-beacon'}}) + '\n' + json.dumps(d) + '\n' for d in docs)
req = urllib.request.Request(es + '/_bulk?refresh=true', data=body.encode(), headers={'Content-Type': 'application/x-ndjson'})
print('errors:', json.load(urllib.request.urlopen(req))['errors'], 'docs:', len(docs))
