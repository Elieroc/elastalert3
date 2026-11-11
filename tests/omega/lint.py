"""Conventions of omega-rules, then `elastalert validate` on every pack. Usage: python3 lint.py [--strict] [pack ...]
--strict: a rule without tests/omega/cases/<name>.yaml is an error (default: a warning)."""
import os, re, subprocess, sys, tempfile
import lib

strict = '--strict' in sys.argv
packs = [a for a in sys.argv[1:] if not a.startswith('--')] or [p for p in lib.PREFIX if os.path.isdir(os.path.join(lib.PACKS, p))]
bin_ = lib.binary()
errors = warnings = total = 0


def err(f, msg):
    global errors
    errors += 1
    print(f'ERROR {os.path.relpath(f, lib.ROOT)}: {msg}')


for pack in packs:
    pdir = os.path.join(lib.PACKS, pack)
    prefix = lib.PREFIX[pack]
    names = {}
    files = lib.rule_files(pdir)
    for f in files:
        total += 1
        stem = os.path.basename(f).rsplit('.', 1)[0]
        if not f.endswith('.yaml'):
            err(f, 'extension must be .yaml')
        if not re.fullmatch(rf'omega-{prefix}(-[a-z0-9]+){{2,}}', stem):
            err(f, f'name must look like omega-{prefix}-<what>-<how> (lowercase, digits, dashes)')
        try:
            r, _ = lib.load(f)
        except Exception as e:
            err(f, f'cannot load: {e}')
            continue
        if r.get('name') != stem:
            err(f, f'name {r.get("name")!r} must equal the file name {stem!r}')
        if stem in names:
            err(f, f'duplicate of {names[stem]}')
        names[stem] = f
        for k in ('type', 'index', 'alert', 'priority', 'mitre_attack', 'omega'):
            if k == 'index' and r.get('type') == 'risk':
                continue  # a risk rule reads the writeback index
            if k not in r:
                err(f, f'missing {k}')
        if r.get('priority') not in (1, 2, 3, 4, 5):
            err(f, 'priority must be 1..5')
        o = r.get('omega') or {}
        for k in ('tier', 'description', 'source', 'false_positives', 'references'):
            if not o.get(k):
                err(f, f'omega.{k} missing or empty')
        tier = o.get('tier')
        if tier not in ('T0', 'T1', 'T2'):
            err(f, 'omega.tier must be T0, T1 or T2')
        alert = r.get('alert')
        score, objs = r.get('risk_score'), r.get('risk_objects')
        if tier == 'T1':
            if alert != []:
                err(f, 'T1 is silent: import common/silent.inc (alert: [])')
            if not (isinstance(score, (int, float)) and 0 < score <= 30) or not objs:
                err(f, 'T1 needs risk_score in 1..30 and risk_objects')
        elif tier in ('T0', 'T2'):
            if not alert:
                err(f, f'{tier} needs an alerter: import common/alert.inc')
            if tier == 'T0' and (not (isinstance(score, (int, float)) and score >= 70) or not objs):
                err(f, 'T0 needs risk_score >= 70 and risk_objects')
            if tier == 'T2' and r.get('type') == 'risk' and (score or objs):
                err(f, 'a risk rule reads risk, it cannot add any')
        if not os.path.exists(os.path.join(lib.CASES, stem + '.yaml')):
            if strict:
                err(f, 'no test case in tests/omega/cases/')
            else:
                warnings += 1
                print(f'warn  {stem}: no test case')
    if files:
        with tempfile.TemporaryDirectory() as t:
            cfg = os.path.join(t, 'config.yaml')
            open(cfg, 'w').write(f'rules_folder: {pdir}\nscan_subdirectories: true\nes_host: 127.0.0.1\nes_port: 9200\n'
                                 'writeback_index: omega_lint\nrun_every: {minutes: 1}\nbuffer_time: {minutes: 15}\n')
            out = subprocess.run([bin_, '--config', cfg, 'validate'], capture_output=True, text=True)
            print(f'{pack}: {(out.stdout + out.stderr).strip().splitlines()[-1] if (out.stdout + out.stderr).strip() else "?"}')
            if out.returncode:
                errors += 1
                print(out.stdout + out.stderr)
    else:
        print(f'{pack}: no rules yet')
print(f'{total} rule(s), {errors} error(s), {warnings} warning(s)')
sys.exit(1 if errors else 0)
