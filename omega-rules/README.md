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
| `linux/` | 115: 48 T0, 63 T1, 4 T2 | Elastic Defend / Auditbeat (process, file, network, DNS lookups), system auth (sshd, sudo, su) | first version |
| `windows/` | 114: 67 T0, 42 T1, 5 T2 | Elastic Defend / Winlogbeat / Sysmon (process, file, registry, network, DNS, named pipes, WMI), Security and System event logs (4624/4625/4662/4697/4698/4732/4768/4769/5140, 1102, 7045), PowerShell script block logging (4104) | first version |
| `web/`, `firewall/` | - | - | planned |

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
