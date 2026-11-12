"""Shared helpers of the omega-rules tools: repo paths, rule loading with `import:` resolved (same merge as elastalert)."""
import os, yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
PACKS = os.path.join(ROOT, 'omega-rules')
CASES = os.path.join(ROOT, 'tests', 'omega', 'cases')
PREFIX = {'linux': 'lnx', 'windows': 'win', 'web': 'web', 'firewall': 'fw'}


def binary(arg=None):
    for c in (arg, os.environ.get('ELASTALERT'), os.path.join(ROOT, 'target', 'release', 'elastalert'),
              os.path.join(ROOT, 'target', 'debug', 'elastalert')):
        if c and os.path.exists(c):
            return c
    raise SystemExit('no elastalert binary: cargo build, or set ELASTALERT')


def rule_files(pack_dir):
    out = []
    for d, _, fs in os.walk(pack_dir):
        out += [os.path.join(d, f) for f in fs if f.endswith(('.yaml', '.yml'))]
    return sorted(out)


def load(path, _seen=()):
    """Rule as elastalert reads it: imports merged (filters ANDed), the rule's own keys win. Returns (dict, [import files])."""
    raw = yaml.safe_load(open(path)) or {}
    imp = raw.pop('import', None)
    merged, files = {}, []
    for i in ([imp] if isinstance(imp, str) else imp or []):
        p = os.path.normpath(os.path.join(os.path.dirname(path), i))
        if p in _seen:
            raise ValueError(f'import loop at {p}')
        base, sub = load(p, _seen + (path,))
        files += [p] + sub
        flt = merged.get('filter', []) + base.pop('filter', [])
        merged.update(base)
        if flt:
            merged['filter'] = flt
    flt = merged.get('filter', []) + raw.pop('filter', [])
    merged.update(raw)
    if flt:
        merged['filter'] = flt
    return merged, files


HERE = os.path.dirname(os.path.abspath(__file__))
BENIGN_BASE = {
    'linux': {
        'process': {'host.os.type': 'linux', 'host.name': 'srv9', 'event.category': 'process', 'event.type': 'start'},
        'file': {'host.os.type': 'linux', 'host.name': 'srv9', 'event.category': 'file', 'event.type': 'creation'},
        'network': {'host.os.type': 'linux', 'host.name': 'srv9', 'event.category': 'network', 'event.action': 'connection_attempted'},
        'auth': {'host.name': 'srv9', 'event.category': 'authentication'},
    },
    'windows': {
        'process': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'process', 'event.type': 'start'},
        'file': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'file', 'event.type': 'creation'},
        'registry': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'registry', 'event.type': 'change'},
        'network': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'network', 'event.action': 'connection_attempted'},
        'dns': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'network', 'event.action': 'lookup_requested'},
        'auth': {'host.name': 'win9', 'event.category': 'authentication', 'event.provider': 'Microsoft-Windows-Security-Auditing'},
        'powershell': {'host.os.type': 'windows', 'host.name': 'win9', 'event.category': 'process', 'event.code': '4104'},
    },
    'web': {
        'web': {'host.name': 'web9', 'event.category': 'web'},
        'proxy': {'host.name': 'proxy9', 'event.category': 'web'},
    },
    'firewall': {
        'firewall': {'observer.name': 'fw9', 'observer.type': 'firewall', 'event.category': 'network', 'event.type': 'allowed', 'network.transport': 'tcp'},
    },
}


def nest(flat):
    out = {}
    for k, v in flat.items():
        cur = out
        parts = k.split('.')
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def deep_merge(a, b):
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            deep_merge(a[k], v)
        else:
            a[k] = v
    return a
