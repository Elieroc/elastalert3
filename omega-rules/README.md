# omega-rules

Detection pack shipped with elastalert3. One folder per pack: `linux/`, `windows/`, `web/`, `firewall/`.
Every rule is one self-contained file: index, base filter, indicator lists, exceptions and alerter are all inside it. See `config.example.yaml`.

## Rule files

- Name: `omega-<pack>-<what>-<how>.yaml`, e.g. `omega-lnx-coinminer-execution.yaml`. Pack prefixes: `lnx`, `win`, `web`, `fw`.
  The file name without `.yaml` is the rule `name`. Readable, no numeric ids.
- Fields from ECS. Each rule carries its own `index`, base filter (OS, event category), `exceptions` and `alert`.
  T0 and T2 rules ship with `alert: [debug]`: change it to your alerter (one `sed` over the folder does it). T1 rules have `alert: []`.
- Required keys: `name`, `type`, `alert`, `priority` (1 critical .. 5 informational), `mitre_attack`, `omega`.
- `omega:` block (ignored by the engine, checked by `tests/omega/lint.py`):
  ```yaml
  omega:
    tier: T0              # T0 alert | T1 signal | T2 meta
    description: Execution of a known crypto miner binary or its stratum command line.
    source: [process]     # process | file | network | auditd | auth | web | firewall ...
    false_positives: Security tooling that scans for miner names; exclude it in exceptions.
    references: ["sigma: proc_creation_lnx_coinminer", "https://attack.mitre.org/techniques/T1496/"]
  ```

## Tiers

| Tier | Role | `alert:` | Risk |
|---|---|---|---|
| T0 | high fidelity, no legitimate use | `[debug]` to replace | `risk_score` 70-100 |
| T1 | ambiguous behaviour (discovery, curl, chmod) | `[]` (silent: the alert doc is still written) | `risk_score` 5-30 |
| T2 | `risk` rules over alerts, anomaly rules (`beacon`, `log_loss`) | `[debug]` to replace | optional (`beacon`, `log_loss`: 40-50); a `risk` rule reads risk, it adds none |

Silent T1 rules still write their doc to the writeback index with `risk_objects`; the T2 `risk` rules read it.

## Packs

| Pack | Rules | Data sources (ECS) | State |
|---|---|---|---|
| `linux/` | 122: 52 T0, 66 T1, 4 T2 | Elastic Defend / Auditbeat (process, file, network, DNS lookups), system auth (sshd, sudo, su) | first version |
| `windows/` | 150: 87 T0, 58 T1, 5 T2 | Elastic Defend / Winlogbeat / Sysmon (process, file, registry, network, DNS, named pipes, WMI), Security and System event logs (4624/4625/4662/4697/4698/4732/4768/4769/5140, 1102, 7045), PowerShell script block logging (4104) | first version |
| `web/` | 90: 17 T0, 62 T1, 11 T2 | Web access logs (nginx, Apache, Tomcat, IIS, Traefik; ECS `event.category: web`, `url.original`/`url.path`/`url.domain`, `http.request.method`, `http.response.status_code`, `http.request.bytes`, `http.response.body.bytes`, `user_agent.original`, `source.ip`, optional GeoIP `source.geo.*` / `source.as.number` and `user.name`) and forward proxy logs (Squid, Zscaler; source `proxy`) | first version |
| `firewall/` | - | - | planned |

Linux covers, with one rule per behaviour and the type of rule that fits it: blacklists of tools and miners
reverse shells, GTFOBins escapes, persistence (cron, systemd, profile, SSH keys, sudoers, PAM,
`ld.so.preload`), defense evasion (log and history tampering, security-tool tampering), thresholds (`frequency`,
`cardinality`), rarity (`new_term` with `max_occurrences`), sequences (`correlation`), `geo_velocity`, `beacon`,
`log_loss`, `active_hours`, and `risk` rules adding the silent signals up per host and per source address.
The T1 signals feed `omega-lnx-host-risk` and `omega-lnx-source-ip-risk`.

Not in this version: `risk_ratio` (needs weeks of alert history to test), `baseline`, `outlier`, a per-user risk rule
(shared accounts like `root` would add the whole fleet up), container/Kubernetes and auditd-only rules.

Windows follows the same tiers and conventions. Fields expected (ECS, as written by Elastic Defend, Winlogbeat and the
Elastic Windows integrations): `host.os.type: windows`, `event.category`, `event.type`, `event.action`, `process.*`
(`name`, `executable`, `command_line`, `parent.name`, `parent.entity_id`), `file.path`/`file.name`/`file.extension`,
`registry.path`/`registry.data.strings`, `destination.ip`/`destination.port`, `dns.question.name`, and for the event logs
`event.code`, `event.provider`, `winlog.logon.type`, `winlog.event_data.*` (`TargetSid`, `ServiceFileName`, `TicketEncryptionType`,
`ShareName`, `Properties`, `TaskContent`, `PipeName`, `GrantedAccess`...) and `powershell.file.script_block_text`.
Process, file, registry, network and DNS rules read `logs-endpoint.events.*`, `winlogbeat-*` and `logs-windows.sysmon_operational-*`;
the log-based rules read `winlogbeat-*` and the `logs-system.*` data streams. Windows names are case-insensitive, so the rules use
case-insensitive `term` and `wildcard` queries (an extra cost on large indices: narrow `index` if needed). The script block field and
`winlog.event_data.*` fields must be searchable as `keyword` (the `.keyword` sub-field or a `keyword` mapping).
Behaviour of note: ransomware (`known-ransom-note-created`, `ransom-note-dropped-in-many-folders`, `ransomware-extension-file-burst`,
`shadow-copy-or-backup-deletion`, `service-and-process-stop-burst`), credential theft (LSASS, SAM/NTDS, DCSync, Kerberoasting, WDigest,
LSA packages), persistence in the registry and WMI, Office/server process trees, and PowerShell script block content.
The T1 signals feed `omega-win-host-risk`, `omega-win-user-risk` and `omega-win-source-ip-risk`.

### LOTTunnels coverage (Linux)

Tunnelling tools from https://lottunnels.github.io/ are covered by four rules: `omega-lnx-self-hosted-or-anonymous-tunnel-tool-execution` (T0, dedicated
tools), `omega-lnx-overlay-or-reverse-proxy-service-client-execution` (T1, dual-use clients such as cloudflared, tailscale, tmate),
`omega-lnx-tunnel-service-command-line` (T0, quick tunnels, `ssh -R` to public tunnel services, reGeorg, gsocket installer) and
`omega-lnx-tunnel-service-domain-lookup` (T1, the LOTTunnels domain list). `chisel`, `ligolo`, `frp`, `ngrok`, `gost`, `iodine`, `dnscat`
and `ptunnel` were already in `omega-lnx-offensive-tool-execution`, and plain `ssh -R/-L/-D` in `omega-lnx-ssh-port-forward-tunnel`.

### LOLBAS coverage

The Windows pack covers the LOLBAS binaries that have a detectable command line: transfers (`certreq`, `certoc`, `desktopimgdownldr`,
`cmdl32`, `ftp`, `finger`, `expand`/`extrac32`/`replace`/`makecab` from UNC paths, `winget`, `AppInstaller`, Squirrel `Update.exe`),
alternate data streams, .NET and SDK tooling (`Microsoft.Workflow.Compiler`, `aspnet_compiler`, `csi`/`rcsi`/`fsi`, `msdeploy`, debuggers,
`vshadow`...), legacy launchers (`pcalua`, `scriptrunner`, `infdefaultinstall`...), `msdt` (Follina), `rundll32` library exports, `mmc` and
`control` from untrusted paths, `mavinject`, `fltmc unload`, `fsutil`/`cipher`, `pnputil`, `mofcomp`, memory-dump tools, `wsl`/`bash` and capture
tools. Binaries that only matter through a DLL planted next to them (`iediagcmd`, `ie4uinit`, `OfflineScannerShell`...) or that
run constantly in normal use (`verclsid`, `msedge_proxy`) have no rule: a command-line rule would be pure noise.

### Rules tied to 2026 exploited vulnerabilities

Exploitation rarely leaves a version string, so these rules look at what the exploit does on the host, and each one
says what the public reports do and do not state (the post-exploitation details of several 2026 CVEs are not published).
Linux: `omega-lnx-root-shell-from-unprivileged-parent` (kernel and setuid local privilege escalations, e.g. Copy Fail
CVE-2026-31431, Fragnesia CVE-2026-46300), `omega-lnx-ssh-password-login-for-root-or-system-account` and
`omega-lnx-ssh-password-login-then-key-or-secret-access` (OpenSSH "SSHole" authentication bypass, CVE-2026-123158; musl-based
systems, fixed in OpenSSH 10.6p2). Windows: `omega-win-system-process-from-unprivileged-parent` (ALPC and update-stack
privilege escalations), `omega-win-ikeext-service-spawns-process` and `omega-win-ike-traffic-from-public-address-received`
(IKE service CVE-2026-33824), `omega-win-explorer-launches-payload-from-shortcut-or-remote-path`,
`omega-win-execution-from-webdav-or-public-unc-path` and `omega-win-shortcut-or-library-file-created-by-archiver-or-browser`
(Windows Shell and Mark-of-the-Web flaws), `omega-win-screenconnect-*` and
`omega-win-backup-server-service-spawns-recon-or-account-command` (remote-support and backup servers). The privilege
rules need `user.id` and `process.parent.user.id` in the process events (ECS fields; check that your sensor fills them).
BitLocker and recovery environment (the WinRE BitLocker bypasses published in 2026 run before the OS boots, so no rule can see
them; the rules cover what happens in the OS around them): `omega-win-bitlocker-protection-weakened`,
`omega-win-bitlocker-recovery-key-read`, `omega-win-winre-tampering-command`, `omega-win-winre-image-or-config-modified`.
The real protection is a pre-boot PIN (TPM + PIN).

## Sources and licences

Logic is derived from Sigma (DRL 1.1: keep the author and the reference) and from ideas in the Elastic detection-rules
(ELv2: logic rewritten, `rule_id` cited as a reference only, no text copied).

## Tests

`tests/omega/` (Python 3 + PyYAML):

```sh
python3 tests/omega/lint.py                       # conventions + `elastalert validate` on every pack
docker run -d --rm --name omega-es -p 19200:9200 -e discovery.type=single-node -e xpack.security.enabled=false \
  -e ES_JAVA_OPTS="-Xms512m -Xmx512m" docker.elastic.co/elasticsearch/elasticsearch:8.15.5
python3 tests/omega/run.py http://127.0.0.1:19200 [rule-name ...]   # positive + benign events per rule
python3 tests/omega/triage.py linux -o /tmp/triage-linux.tsv         # inventory of Sigma + Elastic sources
python3 tests/omega/coverage.py linux --triage /tmp/triage-linux.tsv # ATT&CK techniques the sources cover and we do not
```

Every rule has `tests/omega/cases/<rule-name>.yaml`: documents (`match: true` for the ones the filter must hit; the
others are benign and must not be hit) and optionally `matches: N`, what the rule type must produce.

## Web pack notes

- Tiers: an attempt (payload, probe, scan, tool user agent) is T1, silent, and only adds risk; a success, a chain
  (`correlation`: brute force then login, upload then script, exploit then web shell) or an attack from an internal
  address is T0. T2 holds baselines, log loss, beaconing and the three risk rules (`omega-web-source-ip-risk`,
  `-host-risk` with `risk_ratio`, `-user-risk` with `usual_hours`). The host risk rule also adds up the alerts of the
  `linux` and `windows` packs for the same `host.name`.
- Rule types used: any, blacklist, whitelist, frequency (also with `use_terms_query`), cardinality, percentage_match,
  metric_aggregation, spike, spike_aggregation, flatline, change, new_term (with `max_occurrences` and composite
  fields), correlation, geo_velocity, beacon, baseline, log_loss, outlier, risk, plus `active_hours`.
- Web rules read `logs-*` access indices and `filebeat-*`; narrow `index` to your web logs, since the payload rules use
  wildcards. Behind a load balancer `source.ip` must be the client address (`X-Forwarded-For`), or every per-source
  threshold counts the balancer.
- Rules that need GeoIP or authentication fields (`omega-web-impossible-travel-login`, `-session-country-change`,
  `-admin-access-from-new-network`, `-user-new-browser-or-system`) stay silent when the field is missing.
- Proxy rules (`omega-web-proxy-*`) read `logs-squid.log-*` and `logs-zscaler_zia.web-*`.
- Time windows (`active_hours`, `usual_hours`) default to UTC and Monday to Friday 07:00-19:00: set them to your site.
