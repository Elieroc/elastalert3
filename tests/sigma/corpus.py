"""Converts every rule of a SigmaHQ checkout with `elastalert sigma-convert` and tells how many load.
A rule must either convert or be refused with a message: a panic or a crash fails the run.
No Elasticsearch needed.

Usage: python3 corpus.py path/to/sigma/rules [path/to/elastalert] [--list] [--es http://127.0.0.1:19200]
  --list   also print every refused rule with its reason
  --es URL also ask Elasticsearch to parse the query of every converted rule (_validate/query with rewrite), which
           catches what only the server can: a regular expression Lucene rejects, a malformed wildcard"""
import collections, json, os, re, subprocess, sys, urllib.request

es = None
if '--es' in sys.argv:
    i = sys.argv.index('--es')
    es = sys.argv[i + 1].rstrip('/')
    del sys.argv[i:i + 2]
args = [a for a in sys.argv[1:] if not a.startswith('--')]
root = args[0]
binary = args[1] if len(args) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'target', 'release', 'elastalert')

PIPELINES = {'windows': 'ecs_windows', 'linux': 'ecs_linux'}


def pipeline(path):
    parts = os.path.relpath(path, root).split(os.sep)
    return next((PIPELINES[p] for p in parts if p in PIPELINES), None)


def reason(stderr):
    """The innermost message of the error chain, with the rule name and quoted values taken out so reasons group."""
    line = stderr.strip().splitlines()[-1] if stderr.strip() else 'no message'
    line = re.sub(r'^Error: ', '', line)
    line = line.split(': ')[-1] if line.count(': ') > 1 else line
    return re.sub(r'"[^"]*"|\'[^\']*\'', '"…"', line)


files = sorted(os.path.join(d, f) for d, _, fs in os.walk(root) for f in fs if f.endswith(('.yml', '.yaml')))

def invalid(file, cmd):
    """The server's complaint about the query of a converted rule, or None."""
    q = subprocess.run(cmd + ['--dsl'], capture_output=True, text=True).stdout
    req = urllib.request.Request(es + '/_all/_validate/query?rewrite=true', data=q.encode(), headers={'Content-Type': 'application/json'})
    try:
        r = json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return e.read().decode()[:300]
    return None if r.get('valid') else json.dumps(r.get('explanations', r))[:300]


ok, refused, broken, rejected = 0, collections.Counter(), [], []
listing = []
for f in files:
    cmd = [binary, 'sigma-convert', '--keyword-field', 'message', f]
    if p := pipeline(f):
        cmd[2:2] = ['-p', p]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode == 0:
        ok += 1
        if es and (why := invalid(f, cmd)):
            rejected.append((f, why))
    elif out.returncode == 1 and 'panicked' not in out.stderr:
        r = reason(out.stderr)
        refused[r] += 1
        listing.append((f, r))
    else:
        broken.append((f, out.returncode, out.stderr.strip()[-300:]))

total = len(files)
print(f'{total} rules: {ok} convert ({100 * ok / max(total, 1):.1f}%), {sum(refused.values())} refused, {len(broken)} crashed')
for r, n in refused.most_common(25):
    print(f'{n:6}  {r}')
if '--list' in sys.argv:
    for f, r in listing:
        print(f'refused {os.path.relpath(f, root)}: {r}')
if es:
    print(f'Elasticsearch rejected the query of {len(rejected)} converted rules')
for f, why in rejected:
    print(f'INVALID {os.path.relpath(f, root)}: {why}')
for f, code, err in broken:
    print(f'CRASH {f} (exit {code}): {err}')
sys.exit(1 if broken or rejected else 0)
