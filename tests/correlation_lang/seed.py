"""Writes a correlation scenario with EQL and ES|QL leaves to Elasticsearch (stdlib only). Usage: python3 seed.py http://127.0.0.1:19200
Window 2026-10-01T08:00Z.., key = host.name, index logs-corrlang (minutes after 08:01):
  h1  failure 0,1,2   success 5   tool 7
  h2  success 1       tool 3
  h3  success 0       failure 1,2,3
  h4  failure 0,1,2   success 4
Run (throwaway ES: docker run -d --rm -p 19200:9200 -e discovery.type=single-node -e xpack.security.enabled=false
docker.elastic.co/elasticsearch/elasticsearch:8.15.3), from tests/correlation_lang:
  elastalert --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z
Expected, per rule (the `dsl-*` twins use only Query DSL leaves and must give the same hosts):
  eql-then-ok    (fail x3 THEN eql success)           h1, h4
  esql-then-tool (fail x3 THEN esql tool)             h1
  eql-and-esql   (eql success AND esql tool)          h1, h2
  dsl-then-ok, dsl-then-tool, dsl-and: same hosts as their twin."""
import json, sys, urllib.request
from datetime import datetime, timedelta, timezone

es = sys.argv[1].rstrip('/')
def call(method, path, body=None, ctype='application/json'):
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(es + path, data=data, method=method, headers={'Content-Type': ctype})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        if e.code == 404 and method == 'DELETE':
            return {}
        raise
call('DELETE', '/logs-corrlang')
call('PUT', '/logs-corrlang', {'mappings': {'properties': {'@timestamp': {'type': 'date'}, 'host': {'properties': {'name': {'type': 'keyword'}}},
    'event': {'properties': {'category': {'type': 'keyword'}, 'outcome': {'type': 'keyword'}}}, 'tool': {'type': 'keyword'}}}})
t0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
def ev(host, minute, **extra):
    ts = t0 + timedelta(minutes=minute + 1)  # the range is gt start: nothing at exactly 08:00
    return {'@timestamp': ts.isoformat().replace('+00:00', 'Z'), 'host': {'name': host}, **extra}
fail = lambda h, m: ev(h, m, event={'category': 'authentication', 'outcome': 'failure'})
ok = lambda h, m: ev(h, m, event={'category': 'authentication', 'outcome': 'success'})
tool = lambda h, m: ev(h, m, tool='mimikatz')
docs = [fail('h1', i) for i in range(3)] + [ok('h1', 5), tool('h1', 7), ok('h2', 1), tool('h2', 3), ok('h3', 0)]
docs += [fail('h3', i) for i in (1, 2, 3)] + [fail('h4', i) for i in range(3)] + [ok('h4', 4)]
body = ''.join(json.dumps({'index': {'_index': 'logs-corrlang'}}) + '\n' + json.dumps(d) + '\n' for d in docs)
print('errors:', call('POST', '/_bulk?refresh=true', body, 'application/x-ndjson')['errors'], 'docs:', len(docs))
