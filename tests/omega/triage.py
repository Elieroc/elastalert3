"""Inventory of the Sigma and Elastic detection-rules sources for one pack, as TSV, to pick and merge rules.
Usage: python3 triage.py {linux|windows|web|firewall} [-o FILE] [--sigma DIR] [--elastic DIR]
Columns: source, id, level, status, kind, datasource, techniques, title, path.
The sources are third-party (Sigma DRL 1.1, Elastic ELv2): read them, rewrite the logic, never copy files into omega-rules."""
import argparse, os, sys, tomllib
import yaml

ap = argparse.ArgumentParser()
ap.add_argument('pack', choices=['linux', 'windows', 'web', 'firewall'])
ap.add_argument('-o', '--output')
ap.add_argument('--sigma', default=os.path.expanduser('~/Documents/IT/Ressources/sigma'))
ap.add_argument('--elastic', default=os.path.expanduser('~/Documents/IT/Ressources/detection-rules'))
a = ap.parse_args()

SIGMA_DIRS = ['rules', 'rules-threat-hunting', 'rules-emerging-threats', 'rules-dfir']
FW_PRODUCTS = {'cisco', 'fortinet', 'paloalto', 'checkpoint', 'juniper', 'sonicwall', 'sophos', 'pfsense', 'opnsense'}


def sigma_pack(ls):
    prod, cat = (ls.get('product') or '').lower(), (ls.get('category') or '').lower()
    if a.pack == 'linux':
        return prod == 'linux'
    if a.pack == 'windows':
        return prod == 'windows'
    if a.pack == 'web':
        return cat == 'webserver' or prod in ('apache', 'nginx', 'iis')
    return cat == 'firewall' or prod in FW_PRODUCTS


WEB_TAGS = ('domain: web', 'threat: web shell', 'threat: web application attack', 'service: nginx', 'service: iis',
            'service: apache http server', 'service: apache tomcat', 'data source: nginx', 'data source: apache', 'data source: iis')
FW_TAGS = ('data source: fortinet', 'data source: pfsense', 'data source: suricata', 'data source: zeek', 'data source: palo alto',
           'data source: check point', 'data source: cisco', 'use case: network security monitoring')


def elastic_pack(path, rule):
    tags = {t.lower() for t in rule.get('tags', [])}
    if a.pack == 'linux':
        return 'os: linux' in tags
    if a.pack == 'windows':
        return 'os: windows' in tags
    if a.pack == 'web':
        return any(t.startswith(WEB_TAGS) for t in tags)
    return any(t.startswith(FW_TAGS) for t in tags)


rows = []
for sub in SIGMA_DIRS:
    for d, _, fs in os.walk(os.path.join(a.sigma, sub)):
        for f in fs:
            if not f.endswith('.yml'):
                continue
            p = os.path.join(d, f)
            try:
                docs = [x for x in yaml.safe_load_all(open(p)) if isinstance(x, dict)]
            except Exception:
                continue
            for r in docs:
                ls = r.get('logsource')
                if not isinstance(ls, dict) or not sigma_pack(ls):
                    continue
                techs = sorted({t[7:].upper() for t in r.get('tags', []) if t.lower().startswith('attack.t')})
                ds = ls.get('category') or ls.get('service') or ''
                rows.append(('sigma', r.get('id', ''), r.get('level', ''), r.get('status', ''), sub, ds, ','.join(techs),
                             r.get('title', ''), os.path.relpath(p, a.sigma)))
for d, _, fs in os.walk(os.path.join(a.elastic, 'rules')):
    if '_deprecated' in d:
        continue
    for f in fs:
        if not f.endswith('.toml'):
            continue
        p = os.path.join(d, f)
        try:
            t = tomllib.load(open(p, 'rb'))
        except Exception:
            continue
        rule = t.get('rule', {})
        if not elastic_pack(p, rule):
            continue
        techs = set()
        for th in rule.get('threat', []):
            for te in th.get('technique', []):
                techs.add(te['id'])
                techs.update(s['id'] for s in te.get('subtechnique', []))
        idx = ','.join(rule.get('index', [])[:3])
        rows.append(('elastic', rule.get('rule_id', ''), rule.get('severity', ''), t.get('metadata', {}).get('maturity', ''),
                     rule.get('type', ''), idx, ','.join(sorted(techs)), rule.get('name', ''), os.path.relpath(p, a.elastic)))
rows.sort(key=lambda r: (r[6], r[0], r[7]))
out = open(a.output, 'w') if a.output else sys.stdout
out.write('source\tid\tlevel\tstatus\tkind\tdatasource\ttechniques\ttitle\tpath\n')
for r in rows:
    out.write('\t'.join(x.replace('\t', ' ') for x in r) + '\n')
n = {s: sum(1 for r in rows if r[0] == s) for s in ('sigma', 'elastic')}
techs = {t for r in rows for t in r[6].split(',') if t}
print(f'{a.pack}: {n["sigma"]} sigma, {n["elastic"]} elastic, {len(techs)} distinct techniques', file=sys.stderr)
