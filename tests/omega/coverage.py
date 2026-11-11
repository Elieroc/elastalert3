"""ATT&CK coverage of a pack: techniques of its rules (mitre_attack) against the techniques the sources detect.
Usage: python3 coverage.py {linux|windows|web|firewall} [--triage FILE] [--layer FILE]
--triage: TSV from triage.py; lists the techniques the sources cover and the pack does not, most-covered first.
--layer: also writes an ATT&CK Navigator layer (elastalert mitre-layer)."""
import argparse, collections, os, subprocess, sys, tempfile
import lib

ap = argparse.ArgumentParser()
ap.add_argument('pack', choices=list(lib.PREFIX))
ap.add_argument('--triage')
ap.add_argument('--layer')
a = ap.parse_args()
pdir = os.path.join(lib.PACKS, a.pack)
have, tier = collections.defaultdict(set), collections.Counter()
for f in lib.rule_files(pdir):
    r, _ = lib.load(f)
    tier[(r.get('omega') or {}).get('tier', '?')] += 1
    for m in r.get('mitre_attack') or []:
        have[m['technique'] if isinstance(m, dict) else m].add(os.path.basename(f)[:-5])
print(f'{a.pack}: {sum(tier.values())} rules ({", ".join(f"{k} {v}" for k, v in sorted(tier.items()))}), {len(have)} techniques')
names = {}
tsv = os.path.join(lib.ROOT, 'attack', 'enterprise-attack.tsv')
tactics = {}
for line in open(tsv):
    if line.startswith('#'):
        continue
    c = line.rstrip('\n').split('\t')
    names[c[0]], tactics[c[0]] = c[1], c[2]
if a.triage:
    want = collections.Counter()
    for line in list(open(a.triage))[1:]:
        c = line.rstrip('\n').split('\t')
        for t in c[6].split(','):
            if t:
                want[t] += 1
    # a rule on T1059.004 also covers its parent in the sense "someone looks at it": only exact IDs and parents are counted
    covered = lambda t: t in have or t.split('.')[0] in have or any(h.startswith(t + '.') for h in have)
    gaps = [(n, t) for t, n in want.items() if not covered(t)]
    gaps.sort(key=lambda x: (-x[0], x[1]))
    by_tactic = collections.defaultdict(list)
    for n, t in gaps:
        by_tactic[tactics.get(t, '?').split(',')[0]].append(f'{t} {names.get(t, "?")} ({n})')
    print(f'{len([t for t in want if covered(t)])}/{len(want)} source techniques covered; gaps by tactic (rules in sources):')
    for tac, items in sorted(by_tactic.items(), key=lambda x: -len(x[1])):
        print(f'  {tac}: ' + '; '.join(items[:8]) + (f'; +{len(items) - 8}' if len(items) > 8 else ''))
if a.layer:
    with tempfile.TemporaryDirectory() as t:
        cfg = os.path.join(t, 'config.yaml')
        open(cfg, 'w').write(f'rules_folder: {pdir}\nscan_subdirectories: true\nes_host: 127.0.0.1\nes_port: 9200\nwriteback_index: x\n'
                             'run_every: {minutes: 1}\nbuffer_time: {minutes: 15}\n')
        subprocess.run([lib.binary(), '--config', cfg, 'mitre-layer', '-o', a.layer, '--name', f'omega-rules {a.pack}'], check=True)
