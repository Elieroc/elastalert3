"""Seeds a throwaway ES, runs the daemon on both rules and checks the matches. Usage: python3 check.py http://127.0.0.1:19200 [path/to/elastalert]"""
import re, subprocess, sys
es = sys.argv[1]
exe = sys.argv[2] if len(sys.argv) > 2 else '../../target/release/elastalert'
subprocess.run([sys.executable, 'seed.py', es], check=True)
out = subprocess.run([exe, '--config', 'config.yaml', '--debug', '--start', '2026-10-10T00:00:00Z', '--end', '2026-10-12T12:05:00Z'],
                     capture_output=True, text=True, timeout=120)
text = out.stdout + out.stderr
matches = sorted(re.findall(r'Alert for (\S+) at .*:\n.*\n\n?Risk of host (\w+): score (\d+)', text))
print(matches)
assert matches == [('risk-off-hours', 'night', '120'), ('risk-off-hours', 'weekend', '120')], f'unexpected matches\n{text[-3000:]}'
print('ok')
