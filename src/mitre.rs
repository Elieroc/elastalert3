//! MITRE ATT&CK: the `mitre_attack` rule option, checked against Enterprise ATT&CK, and the ATT&CK Navigator
//! layer of every rule's techniques (`elastalert mitre-layer`).

use crate::config::Config;
use crate::rule::{self, Rule};
use anyhow::{Context, Result, bail};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

/// Enterprise ATT&CK as shipped: a `#version` line, then `id \t name \t tactics \t status` per technique, where
/// status is empty, `deprecated`, `revoked` or `revoked:<replacement id>`. Regenerated from MITRE's STIX bundle by
/// the ignored test `regenerate_embedded_table`.
const EMBEDDED: &str = include_str!("../attack/enterprise-attack.tsv");

static EMBEDDED_TABLE: LazyLock<Arc<Attack>> = LazyLock::new(|| Arc::new(Attack::from_tsv(EMBEDDED).expect("embedded ATT&CK table parses")));

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Active,
    Deprecated,
    /// Revoked, and the technique that replaces it when MITRE names one.
    Revoked(Option<String>),
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    /// Tactic short names (`initial-access`), in MITRE's order.
    pub tactics: Vec<String>,
    pub status: Status,
}

/// The techniques of one ATT&CK release.
pub struct Attack {
    /// `x_mitre_version` of the bundle, e.g. `20.0`.
    pub version: String,
    techniques: FxHashMap<String, Entry>,
}

impl Attack {
    /// The table built into the binary.
    pub fn embedded() -> Arc<Attack> {
        EMBEDDED_TABLE.clone()
    }

    /// `mitre_attack_data`: an `enterprise-attack.json` STIX bundle from MITRE, instead of the built-in table.
    pub fn from_stix_file(path: &Path) -> Result<Attack> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading mitre_attack_data {}", path.display()))?;
        let v: Value = serde_json::from_str(&text).with_context(|| format!("parsing mitre_attack_data {}", path.display()))?;
        Self::from_stix(&v).with_context(|| format!("mitre_attack_data {}", path.display()))
    }

    pub fn from_stix(bundle: &Value) -> Result<Attack> {
        let objects = bundle.get("objects").and_then(Value::as_array).context("not a STIX bundle: no objects list")?;
        let mut version = String::from("unknown");
        let mut ids: FxHashMap<&str, String> = FxHashMap::default();
        let mut techniques = FxHashMap::default();
        for o in objects {
            match o["type"].as_str() {
                Some("x-mitre-collection") => {
                    if let Some(v) = o["x_mitre_version"].as_str() {
                        version = v.to_string();
                    }
                }
                Some("attack-pattern") => {
                    let refs = o["external_references"].as_array().into_iter().flatten();
                    let Some(id) = refs.filter(|r| r["source_name"] == "mitre-attack").find_map(|r| r["external_id"].as_str()) else { continue };
                    let tactics = o["kill_chain_phases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|k| k["kill_chain_name"] == "mitre-attack")
                        .filter_map(|k| k["phase_name"].as_str().map(String::from))
                        .collect();
                    let status = if o["revoked"] == true {
                        Status::Revoked(None)
                    } else if o["x_mitre_deprecated"] == true {
                        Status::Deprecated
                    } else {
                        Status::Active
                    };
                    if let Some(stix_id) = o["id"].as_str() {
                        ids.insert(stix_id, id.to_string());
                    }
                    let name = o["name"].as_str().unwrap_or_default().to_string();
                    techniques.insert(id.to_string(), Entry { name, tactics, status });
                }
                _ => {}
            }
        }
        for o in objects.iter().filter(|o| o["type"] == "relationship" && o["relationship_type"] == "revoked-by") {
            let (Some(old), Some(new)) = (o["source_ref"].as_str().and_then(|s| ids.get(s)), o["target_ref"].as_str().and_then(|s| ids.get(s))) else { continue };
            if let Some(e) = techniques.get_mut(old) {
                e.status = Status::Revoked(Some(new.clone()));
            }
        }
        if techniques.is_empty() {
            bail!("no ATT&CK technique in the bundle");
        }
        Ok(Attack { version, techniques })
    }

    fn from_tsv(text: &str) -> Result<Attack> {
        let mut version = String::from("unknown");
        let mut techniques = FxHashMap::default();
        for line in text.lines().filter(|l| !l.is_empty()) {
            if let Some(v) = line.strip_prefix("#version\t") {
                version = v.to_string();
                continue;
            }
            let mut cols = line.split('\t');
            let (Some(id), Some(name), Some(tactics), Some(status)) = (cols.next(), cols.next(), cols.next(), cols.next()) else { bail!("bad ATT&CK table line {line:?}") };
            let status = match status {
                "" => Status::Active,
                "deprecated" => Status::Deprecated,
                "revoked" => Status::Revoked(None),
                s => Status::Revoked(Some(s.strip_prefix("revoked:").with_context(|| format!("bad status {s:?}"))?.to_string())),
            };
            let tactics = tactics.split(',').filter(|t| !t.is_empty()).map(String::from).collect();
            techniques.insert(id.to_string(), Entry { name: name.to_string(), tactics, status });
        }
        Ok(Attack { version, techniques })
    }

    #[cfg(test)]
    fn to_tsv(&self) -> String {
        let mut ids: Vec<&String> = self.techniques.keys().collect();
        ids.sort();
        let mut out = format!("#version\t{}\n", self.version);
        for id in ids {
            let e = &self.techniques[id];
            let status = match &e.status {
                Status::Active => String::new(),
                Status::Deprecated => "deprecated".into(),
                Status::Revoked(None) => "revoked".into(),
                Status::Revoked(Some(r)) => format!("revoked:{r}"),
            };
            out.push_str(&format!("{id}\t{}\t{}\t{status}\n", e.name.replace(['\t', '\n'], " "), e.tactics.join(",")));
        }
        out
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.techniques.get(id)
    }

    /// Navigator's `versions.attack`: the major version.
    fn major(&self) -> &str {
        self.version.split('.').next().unwrap_or(&self.version)
    }
}

/// One technique of a rule's `mitre_attack`.
#[derive(Clone, Debug, PartialEq)]
pub struct Technique {
    /// `T1059` or `T1059.001`.
    pub id: String,
    pub name: String,
    /// The tactics the rule files it under: the one it names, else every tactic of the technique.
    pub tactics: Vec<String>,
}

impl Technique {
    pub fn url(&self) -> String {
        format!("https://attack.mitre.org/techniques/{}/", self.id.replace('.', "/"))
    }
}

pub fn is_technique_id(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => b[0] == b'T' && digits(1..5),
        9 => b[0] == b'T' && digits(1..5) && b[5] == b'.' && digits(6..9),
        _ => false,
    }
}

/// `mitre_attack`: a technique ID, or a list of IDs and `{technique: ID, tactic: name}` maps. Unknown techniques and
/// tactics are rejected; deprecated and revoked ones load with a warning, so a newer ATT&CK release never stops a rule.
pub fn parse(value: Option<&Value>, attack: &Attack, rule_name: &str) -> Result<Vec<Technique>> {
    let items: Vec<&Value> = match value {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v @ Value::String(_)) => vec![v],
        Some(_) => bail!("mitre_attack must be a technique ID or a list of them"),
    };
    let mut out: Vec<Technique> = Vec::new();
    for item in items {
        let (id, tactic) = match item {
            Value::String(s) => (s.as_str(), None),
            Value::Object(m) => {
                if let Some(k) = m.keys().find(|k| !matches!(k.as_str(), "technique" | "tactic")) {
                    bail!("mitre_attack: option {k} is not supported (technique, tactic)");
                }
                let id = m.get("technique").and_then(Value::as_str).context("mitre_attack: an entry given as a map needs technique: <ID>")?;
                let tactic = match m.get("tactic") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(t)) => Some(t.trim().to_ascii_lowercase().replace([' ', '_'], "-")),
                    Some(_) => bail!("mitre_attack: tactic of {id} must be a string"),
                };
                (id, tactic)
            }
            _ => bail!("mitre_attack entries must be technique IDs or maps like {{technique: T1078, tactic: initial-access}}"),
        };
        let id = id.trim().to_ascii_uppercase();
        if !is_technique_id(&id) {
            bail!("mitre_attack: {id:?} is not a technique ID like T1059 or T1059.001");
        }
        let Some(entry) = attack.get(&id) else { bail!("mitre_attack: {id} is not a technique of Enterprise ATT&CK {}", attack.version) };
        match &entry.status {
            Status::Active => {}
            Status::Deprecated => log::warn!("Rule {rule_name}: mitre_attack {id} ({}) is deprecated in ATT&CK {}", entry.name, attack.version),
            Status::Revoked(None) => log::warn!("Rule {rule_name}: mitre_attack {id} ({}) is revoked in ATT&CK {}", entry.name, attack.version),
            Status::Revoked(Some(new)) => log::warn!("Rule {rule_name}: mitre_attack {id} ({}) is revoked in ATT&CK {}, use {new}", entry.name, attack.version),
        }
        let tactics = match tactic {
            Some(t) if entry.status == Status::Active && !entry.tactics.contains(&t) => {
                bail!("mitre_attack: {id} ({}) is not under the tactic {t}; its tactics: {}", entry.name, entry.tactics.join(", "))
            }
            Some(t) => vec![t],
            None => entry.tactics.clone(),
        };
        match out.iter_mut().find(|t| t.id == id) {
            Some(seen) => {
                for t in tactics {
                    if !seen.tactics.contains(&t) {
                        seen.tactics.push(t);
                    }
                }
            }
            None => out.push(Technique { id, name: entry.name.clone(), tactics }),
        }
    }
    Ok(out)
}

/// What the writeback alert document stores: `{techniques: [...], tactics: [...]}`.
pub fn writeback(techniques: &[Technique]) -> Option<Value> {
    if techniques.is_empty() {
        return None;
    }
    let tactics: BTreeSet<&str> = techniques.iter().flat_map(|t| t.tactics.iter().map(String::as_str)).collect();
    Some(json!({"techniques": techniques.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), "tactics": tactics}))
}

/// Tags in Sigma's spelling, for alerters that take tags: `attack.t1059.001`, then `attack.execution`.
pub fn tags(techniques: &[Technique]) -> Vec<String> {
    let tactics: BTreeSet<String> = techniques.iter().flat_map(|t| t.tactics.iter().map(|x| format!("attack.{}", x.replace('-', "_")))).collect();
    techniques.iter().map(|t| format!("attack.{}", t.id.to_ascii_lowercase())).chain(tactics).collect()
}

/// `mitre_attack` as Jinja templates see it: `[{id, name, tactics, url}]`.
pub fn jinja(techniques: &[Technique]) -> Value {
    Value::Array(techniques.iter().map(|t| json!({"id": t.id, "name": t.name, "tactics": t.tactics, "url": t.url()})).collect())
}

#[derive(clap::Args)]
pub struct LayerArgs {
    /// Write the layer to this file instead of stdout
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,
    /// Layer name shown in Navigator
    #[arg(long, default_value = "elastalert3 rules")]
    name: String,
    /// Also count the rules with is_enabled: false
    #[arg(long = "include-disabled")]
    include_disabled: bool,
}

/// An ATT&CK Navigator layer (format 4.5): one cell per technique and tactic, scored with the number of rules.
pub fn layer(rules: &[Rule], name: &str, attack: &Attack) -> Value {
    let mut cells: BTreeMap<(&str, &str), Vec<&Rule>> = BTreeMap::new();
    for r in rules {
        for t in &r.mitre_attack {
            for tactic in &t.tactics {
                cells.entry((t.id.as_str(), tactic.as_str())).or_default().push(r);
            }
        }
    }
    let label = |r: &Rule| {
        let disabled = r.raw.get("is_enabled").and_then(Value::as_bool) == Some(false);
        if disabled { format!("{} (disabled)", r.name) } else { r.name.clone() }
    };
    let techniques: Vec<Value> = cells
        .iter()
        .map(|((id, tactic), rs)| {
            json!({
                "techniqueID": id,
                "tactic": tactic,
                "score": rs.len(),
                "comment": rs.iter().map(|r| label(r)).collect::<Vec<_>>().join(", "),
                "metadata": rs.iter().map(|r| json!({"name": "rule", "value": format!("{} ({})", label(r), r.file.display())})).collect::<Vec<_>>(),
            })
        })
        .collect();
    let covered = rules.iter().filter(|r| !r.mitre_attack.is_empty()).count();
    json!({
        "name": name,
        "versions": {"attack": attack.major(), "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": format!("ATT&CK techniques of {covered} of {} elastalert3 rules (mitre_attack option); score = number of rules", rules.len()),
        "sorting": 3,
        "layout": {"layout": "side", "showID": true, "showName": true, "expandedSubtechniques": "annotated"},
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#3182bd"], "minValue": 0, "maxValue": cells.values().map(Vec::len).max().unwrap_or(1)},
        "legendItems": [],
        "metadata": [{"name": "generated by", "value": concat!("elastalert3 ", env!("CARGO_PKG_VERSION"))}],
    })
}

/// `elastalert mitre-layer`: loads every rule (no Elasticsearch) and writes their Navigator layer.
pub fn layer_cmd(args: &LayerArgs, conf: &Config) -> Result<()> {
    let mut rules: Vec<Rule> = Vec::new();
    for file in rule::discover(conf, None)? {
        match rule::load(&file, conf) {
            Ok(r) if !args.include_disabled && r.raw.get("is_enabled").and_then(Value::as_bool) == Some(false) => {}
            Ok(r) => rules.push(r),
            Err(e) if conf.skip_invalid => log::error!("Invalid rule file skipped: {}: {e:#}", file.display()),
            Err(e) => bail!("error loading file {}: {e:#}", file.display()),
        }
    }
    let layer = layer(&rules, &args.name, &conf.attack);
    let text = serde_json::to_string_pretty(&layer)? + "\n";
    match &args.output {
        Some(path) => {
            std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
            let covered = rules.iter().filter(|r| !r.mitre_attack.is_empty()).count();
            eprintln!("{}: {} technique cell(s) from {covered} of {} rule(s)", path.display(), layer["techniques"].as_array().map_or(0, Vec::len), rules.len());
        }
        None => print!("{text}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Attack {
        Attack::from_tsv(
            "#version\t20.0\nT1059\tCommand and Scripting Interpreter\texecution\t\nT1059.001\tPowerShell\texecution\t\nT1078\tValid Accounts\tstealth,persistence,privilege-escalation,initial-access\t\nT1066\tIndicator Removal from Tools\tstealth\trevoked:T1027.005\nT1500\tCompile After Delivery\tstealth\tdeprecated\n",
        )
        .unwrap()
    }

    #[test]
    fn embedded_table_loads() {
        let a = Attack::embedded();
        assert!(a.version.starts_with(|c: char| c.is_ascii_digit()), "{}", a.version);
        let ps = a.get("T1059.001").expect("PowerShell");
        assert_eq!((ps.name.as_str(), &ps.status), ("PowerShell", &Status::Active));
        assert!(ps.tactics.contains(&"execution".to_string()));
        assert!(a.techniques.len() > 600);
    }

    #[test]
    fn stix_bundle_with_revocation() {
        let bundle = json!({"objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "20.0"},
            {"type": "attack-pattern", "id": "ap--1", "name": "Old", "revoked": true, "external_references": [{"source_name": "mitre-attack", "external_id": "T1066"}]},
            {"type": "attack-pattern", "id": "ap--2", "name": "New", "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}, {"kill_chain_name": "other", "phase_name": "x"}],
             "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}, {"source_name": "mitre-attack", "external_id": "T1027.005"}]},
            {"type": "attack-pattern", "id": "ap--3", "name": "Gone", "x_mitre_deprecated": true, "external_references": [{"source_name": "mitre-attack", "external_id": "T1500"}]},
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "ap--1", "target_ref": "ap--2"},
        ]});
        let a = Attack::from_stix(&bundle).unwrap();
        assert_eq!(a.version, "20.0");
        assert_eq!(a.get("T1066").unwrap().status, Status::Revoked(Some("T1027.005".into())));
        assert_eq!(a.get("T1027.005").unwrap().tactics, ["stealth"]);
        assert_eq!(a.get("T1500").unwrap().status, Status::Deprecated);
        let back = Attack::from_tsv(&a.to_tsv()).unwrap();
        assert_eq!(back.to_tsv(), a.to_tsv());
        assert!(Attack::from_stix(&json!({"objects": []})).is_err());
    }

    #[test]
    fn parse_forms() {
        let a = table();
        let v = serde_yaml_ng::from_str::<Value>("[t1059.001, {technique: T1078, tactic: Initial Access}, {technique: T1078, tactic: persistence}, T1059.001]").unwrap();
        let got = parse(Some(&v), &a, "r").unwrap();
        assert_eq!(
            got,
            [
                Technique { id: "T1059.001".into(), name: "PowerShell".into(), tactics: vec!["execution".into()] },
                Technique { id: "T1078".into(), name: "Valid Accounts".into(), tactics: vec!["initial-access".into(), "persistence".into()] },
            ]
        );
        assert_eq!(parse(Some(&json!("T1078")), &a, "r").unwrap()[0].tactics.len(), 4);
        assert!(parse(None, &a, "r").unwrap().is_empty());
        // deprecated and revoked techniques still load
        assert_eq!(parse(Some(&json!(["T1066", "T1500"])), &a, "r").unwrap().len(), 2);
    }

    #[test]
    fn parse_rejects() {
        let a = table();
        for (v, msg) in [
            (json!(5), "must be a technique ID"),
            (json!(["T59"]), "not a technique ID"),
            (json!(["T1059.1"]), "not a technique ID"),
            (json!(["T9999"]), "not a technique of Enterprise ATT&CK 20.0"),
            (json!([{"technique": "T1059.001", "tactic": "persistence"}]), "not under the tactic persistence; its tactics: execution"),
            (json!([{"tactic": "execution"}]), "needs technique"),
            (json!([{"technique": "T1059", "subtechnique": "001"}]), "option subtechnique is not supported"),
            (json!([["T1059"]]), "entries must be"),
        ] {
            let err = format!("{:#}", parse(Some(&v), &a, "r").unwrap_err());
            assert!(err.contains(msg), "{v}: {err}");
        }
    }

    #[test]
    fn writeback_tags_and_jinja() {
        let t = parse(Some(&json!(["T1059.001", {"technique": "T1078", "tactic": "initial-access"}])), &table(), "r").unwrap();
        assert_eq!(writeback(&t), Some(json!({"techniques": ["T1059.001", "T1078"], "tactics": ["execution", "initial-access"]})));
        assert_eq!(writeback(&[]), None);
        assert_eq!(tags(&t), ["attack.t1059.001", "attack.t1078", "attack.execution", "attack.initial_access"]);
        assert_eq!(jinja(&t)[0], json!({"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "url": "https://attack.mitre.org/techniques/T1059/001/"}));
    }

    fn rules(specs: &[(&str, &str)]) -> (Vec<Rule>, Config) {
        let dir = std::env::temp_dir().join(format!("ea-mitre-{}-{}", std::process::id(), specs[0].0));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let rules = specs
            .iter()
            .map(|(name, extra)| {
                let file = dir.join(format!("{name}.yaml"));
                std::fs::write(&file, format!("name: {name}\ntype: any\nindex: logs-*\nalert: debug\n{extra}")).unwrap();
                rule::load(&file, &conf).unwrap()
            })
            .collect();
        std::fs::remove_dir_all(dir).ok();
        (rules, conf)
    }

    #[test]
    fn navigator_layer() {
        let (rs, conf) = rules(&[
            ("a", "mitre_attack: [T1059.001, {technique: T1078, tactic: initial-access}]\n"),
            ("b", "mitre_attack: T1059.001\nis_enabled: false\n"),
            ("c", ""),
        ]);
        let l = layer(&rs, "cov", &conf.attack);
        assert_eq!((&l["name"], &l["domain"], &l["versions"]["layer"]), (&json!("cov"), &json!("enterprise-attack"), &json!("4.5")));
        assert_eq!(l["versions"]["attack"], json!(conf.attack.major()));
        let cells: Vec<_> = l["techniques"].as_array().unwrap().iter().map(|t| (t["techniqueID"].clone(), t["tactic"].clone(), t["score"].clone(), t["comment"].clone())).collect();
        assert_eq!(
            cells,
            [
                (json!("T1059.001"), json!("execution"), json!(2), json!("a, b (disabled)")),
                (json!("T1078"), json!("initial-access"), json!(1), json!("a")),
            ]
        );
        assert_eq!(l["techniques"][1]["metadata"][0]["name"], json!("rule"));
        assert_eq!(l["gradient"]["maxValue"], json!(2));
        assert!(l["description"].as_str().unwrap().contains("2 of 3"));
    }

    #[test]
    fn rule_option_is_checked_at_load() {
        let (rs, _) = rules(&[("ok", "mitre_attack: [T1059.001]\n")]);
        assert_eq!(rs[0].mitre_attack[0].tactics, ["execution"]);
        let dir = std::env::temp_dir().join(format!("ea-mitre-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("bad.yaml");
        std::fs::write(&file, "name: bad\ntype: any\nindex: logs-*\nalert: debug\nmitre_attack: [T0001]\n").unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let err = format!("{:#}", rule::load(&file, &conf).err().unwrap());
        std::fs::remove_dir_all(dir).ok();
        assert!(err.contains("T0001 is not a technique"), "{err}");
    }

    /// Rewrites `attack/enterprise-attack.tsv` from MITRE's bundle:
    /// `ATTACK_STIX=enterprise-attack.json cargo test regenerate_embedded_table -- --ignored`
    /// (https://github.com/mitre-attack/attack-stix-data, `enterprise-attack/enterprise-attack.json`).
    #[test]
    #[ignore]
    fn regenerate_embedded_table() {
        let path = std::env::var("ATTACK_STIX").expect("ATTACK_STIX=<path of enterprise-attack.json>");
        let a = Attack::from_stix_file(Path::new(&path)).unwrap();
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/attack/enterprise-attack.tsv"), a.to_tsv()).unwrap();
    }
}
