"""Writes a risk scenario to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
Events are dated a few minutes before now, so run the daemon live (throwaway ES: docker run -d --rm -p 19200:9200
-e discovery.type=single-node -e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3):
  elastalert --config config.yaml create-index   (once)
  elastalert --config config.yaml                (let it run about 3 minutes: the risk rule waits query_delay 10 s)
Sources: mimikatz 50, psexec 40, whoami 25 (realert 10 min per host), lolbin 60 (aggregated for 1 minute).
  h1: mimikatz + psexec + whoami          -> 115, 3 rules      -> host-risk alert
  h2: mimikatz twice (the 2nd is silenced) -> 100, 1 rule       -> none (min_distinct_rules: 2)
  h3: mimikatz twice + psexec              -> 140, 2 rules, 3 alerts -> host-risk alert (the silenced match counts)
  h4: lolbin twice (one aggregated alert) + whoami -> 145, 2 rules, 3 alerts -> host-risk alert
  h5: whoami                               -> 25                -> none
Check the alert docs: curl 127.0.0.1:19200/elastalert_risk/_search?q=risk_objects.value:h1 (risk_objects on the alert doc;
the silenced and aggregated matches are separate docs with risk_only: true, alert_sent: true)."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es = sys.argv[1].rstrip('/')
def call(method, path, body=None, ctype='application/json'):
    req = urllib.request.Request(es + path, data=body, method=method, headers={'Content-Type': ctype})
    return json.load(urllib.request.urlopen(req))
call('PUT', '/logs-risk', json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'event': {'properties': {'code': {'type': 'keyword'}}}, 'host': {'properties': {'name': {'type': 'keyword'}}}, 'user': {'properties': {'name': {'type': 'keyword'}}}}}}).encode())
now = datetime.now(timezone.utc)
events = [('h1', 'alice', 'mimikatz'), ('h1', 'bob', 'psexec'), ('h1', 'bob', 'whoami'),
          ('h2', 'carol', 'mimikatz'), ('h2', 'carol', 'mimikatz'),
          ('h3', 'dave', 'mimikatz'), ('h3', 'dave', 'mimikatz'), ('h3', 'dave', 'psexec'),
          ('h4', 'erin', 'lolbin'), ('h4', 'erin', 'lolbin'), ('h4', 'erin', 'whoami'),
          ('h5', 'frank', 'whoami')]
body = ''
for i, (host, user, code) in enumerate(events):
    t = (now - timedelta(minutes=5) + timedelta(seconds=i * 10)).isoformat(timespec='seconds').replace('+00:00', 'Z')
    body += json.dumps({'index': {'_index': 'logs-risk'}}) + '\n' + json.dumps({'@timestamp': t, 'host': {'name': host}, 'user': {'name': user}, 'event': {'code': code}}) + '\n'
print('errors:', call('POST', '/_bulk?refresh=true', body.encode(), 'application/x-ndjson')['errors'], 'docs:', len(events))
