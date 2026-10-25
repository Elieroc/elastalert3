//! Sigma processing pipelines: how the field names and the logsource of a Sigma rule map onto your index. A subset of
//! pySigma's pipeline format; a transformation outside it makes the rule fail to load.
//!
//! Types: `field_name_mapping`, `field_name_prefix`, `field_name_suffix`, `add_condition`, and `set_index` (ElastAlert 3:
//! the `index` of the rule when it has none). `rule_conditions` can only be `logsource` ones.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

const BUILT_IN: &[(&str, &str)] = &[
    ("ecs_windows", include_str!("pipelines/ecs_windows.yml")),
    ("sysmon", include_str!("pipelines/sysmon.yml")),
    ("ecs_linux", include_str!("pipelines/ecs_linux.yml")),
];

/// Where a rule comes from, as far as pipelines care.
#[derive(Debug, Default, PartialEq)]
pub struct LogSource {
    pub category: Option<String>,
    pub product: Option<String>,
    pub service: Option<String>,
}

impl LogSource {
    pub fn from_rule(rule: &Map<String, Value>) -> Result<Self> {
        let Some(v) = rule.get("logsource") else { return Ok(Self::default()) };
        let Value::Object(m) = v else { bail!("logsource must be a map") };
        let get = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
        Ok(LogSource { category: get("category"), product: get("product"), service: get("service") })
    }

    /// Every attribute the condition names is the rule's, ignoring case.
    fn matches(&self, c: &LogSource) -> bool {
        let same = |want: &Option<String>, have: &Option<String>| want.as_ref().is_none_or(|w| have.as_ref().is_some_and(|h| h.eq_ignore_ascii_case(w)));
        same(&c.category, &self.category) && same(&c.product, &self.product) && same(&c.service, &self.service)
    }
}

#[derive(Debug)]
enum Action {
    Map(Vec<(String, Vec<String>)>),
    Prefix { text: String, unmapped: bool },
    Suffix { text: String, unmapped: bool },
    Condition(Map<String, Value>),
    Index(String),
}

#[derive(Debug)]
struct Step {
    when: Vec<LogSource>,
    action: Action,
}

#[derive(Debug, Default)]
pub struct Pipeline {
    steps: Vec<Step>,
}

/// A pipeline spec: a built-in name, or a file relative to the rule. Returns the pipeline and its file, if it has one.
pub fn load(spec: &str, base: &Path) -> Result<(Pipeline, Option<PathBuf>)> {
    if let Some((_, text)) = BUILT_IN.iter().find(|(n, _)| *n == spec) {
        return Ok((parse(text).with_context(|| format!("built-in pipeline {spec}"))?, None));
    }
    let file = base.join(spec);
    if !file.is_file() {
        let names: Vec<&str> = BUILT_IN.iter().map(|(n, _)| *n).collect();
        bail!("sigma_pipeline {spec:?} is neither a built-in pipeline ({}) nor a file ({})", names.join(", "), file.display());
    }
    let text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
    Ok((parse(&text).with_context(|| format!("pipeline {}", file.display()))?, Some(file)))
}

fn parse(text: &str) -> Result<Pipeline> {
    let Value::Object(top) = serde_yaml_ng::from_str::<Value>(text)? else { bail!("must be a YAML map") };
    for k in top.keys() {
        if !["name", "priority", "allowed_backends", "transformations"].contains(&k.as_str()) {
            bail!("option {k} is not supported (name, priority, transformations)");
        }
    }
    let Some(Value::Array(list)) = top.get("transformations") else { bail!("missing transformations") };
    let steps = list.iter().enumerate().map(|(i, t)| step(t).with_context(|| format!("transformation {}", i + 1))).collect::<Result<_>>()?;
    Ok(Pipeline { steps })
}

fn only_keys(m: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => bail!("option {k} is not supported (allowed: {})", allowed.join(", ")),
        None => Ok(()),
    }
}

fn string(m: &Map<String, Value>, key: &str) -> Result<String> {
    m.get(key).and_then(Value::as_str).map(str::to_string).with_context(|| format!("{key} must be a string"))
}

fn step(t: &Value) -> Result<Step> {
    let Value::Object(m) = t else { bail!("must be a map") };
    let ty = string(m, "type")?;
    let when = match m.get("rule_conditions") {
        None => vec![],
        Some(Value::Array(a)) => a.iter().map(logsource_condition).collect::<Result<_>>()?,
        Some(_) => bail!("rule_conditions must be a list"),
    };
    let action = match ty.as_str() {
        "field_name_mapping" => {
            only_keys(m, &["id", "type", "rule_conditions", "mapping"])?;
            let Some(Value::Object(map)) = m.get("mapping") else { bail!("mapping must be a map") };
            let mut pairs = Vec::new();
            for (from, to) in map {
                let targets: Vec<String> = match to {
                    Value::String(s) => vec![s.clone()],
                    Value::Array(a) if !a.is_empty() => a.iter().map(|v| v.as_str().map(str::to_string).context("mapping targets must be strings")).collect::<Result<_>>()?,
                    _ => bail!("mapping of {from} must be a field name or a list of them"),
                };
                pairs.push((from.clone(), targets));
            }
            Action::Map(pairs)
        }
        "field_name_prefix" | "field_name_suffix" => {
            let key = if ty == "field_name_prefix" { "prefix" } else { "suffix" };
            only_keys(m, &["id", "type", "rule_conditions", key, "unmapped"])?;
            let text = string(m, key)?;
            let unmapped = m.get("unmapped").and_then(Value::as_bool).unwrap_or(false);
            if key == "prefix" { Action::Prefix { text, unmapped } } else { Action::Suffix { text, unmapped } }
        }
        "add_condition" => {
            only_keys(m, &["id", "type", "rule_conditions", "conditions"])?;
            let Some(Value::Object(c)) = m.get("conditions") else { bail!("conditions must be a map of field to value(s)") };
            Action::Condition(c.clone())
        }
        "set_index" => {
            only_keys(m, &["id", "type", "rule_conditions", "index"])?;
            Action::Index(string(m, "index")?)
        }
        other => bail!("transformation type {other:?} is not supported (field_name_mapping, field_name_prefix, field_name_suffix, add_condition, set_index)"),
    };
    Ok(Step { when, action })
}

fn logsource_condition(v: &Value) -> Result<LogSource> {
    let Value::Object(m) = v else { bail!("rule_conditions entries must be maps") };
    if m.get("type").and_then(Value::as_str) != Some("logsource") {
        bail!("rule_conditions: only type logsource is supported");
    }
    only_keys(m, &["type", "category", "product", "service"])?;
    let get = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(LogSource { category: get("category"), product: get("product"), service: get("service") })
}

/// The pipelines of a rule narrowed to its logsource.
#[derive(Debug, Default)]
pub struct Resolved<'a> {
    steps: Vec<&'a Action>,
    suffix: String,
}

impl<'a> Resolved<'a> {
    pub fn new(pipelines: &'a [Pipeline], source: &LogSource, keyword_suffix: &str) -> Self {
        let steps = pipelines.iter().flat_map(|p| &p.steps).filter(|s| s.when.iter().all(|c| source.matches(c))).map(|s| &s.action).collect();
        Resolved { steps, suffix: keyword_suffix.to_string() }
    }

    /// The fields a Sigma field name stands for: more than one when a mapping lists several (any of them may match).
    pub fn fields(&self, name: &str) -> Vec<String> {
        self.rename(name, &self.suffix)
    }

    /// The same fields as stored in the documents (`include`): without the keyword suffix, which names a sub-field.
    pub fn source_fields(&self, name: &str) -> Vec<String> {
        self.rename(name, "")
    }

    fn rename(&self, name: &str, suffix: &str) -> Vec<String> {
        let mut names: Vec<(String, bool)> = vec![(name.to_string(), false)];
        for action in &self.steps {
            names = match action {
                Action::Map(pairs) => names
                    .into_iter()
                    .flat_map(|(n, m)| match pairs.iter().find(|(from, _)| *from == n) {
                        Some((_, to)) => to.iter().map(|t| (t.clone(), true)).collect(),
                        None => vec![(n, m)],
                    })
                    .collect(),
                Action::Prefix { text, unmapped } => names.into_iter().map(|(n, m)| if *unmapped && m { (n, m) } else { (format!("{text}{n}"), m) }).collect(),
                Action::Suffix { text, unmapped } => names.into_iter().map(|(n, m)| if *unmapped && m { (n, m) } else { (format!("{n}{text}"), m) }).collect(),
                _ => names,
            };
        }
        let mut out: Vec<String> = Vec::new();
        for (n, _) in names {
            let n = format!("{n}{suffix}");
            if !out.contains(&n) {
                out.push(n);
            }
        }
        out
    }

    /// `add_condition` entries, to AND with the detection.
    pub fn conditions(&self) -> Vec<&Map<String, Value>> {
        self.steps.iter().filter_map(|a| if let Action::Condition(c) = a { Some(c) } else { None }).collect()
    }

    /// The `index` a `set_index` step gives; the last one wins.
    pub fn index(&self) -> Option<&str> {
        self.steps.iter().rev().find_map(|a| if let Action::Index(i) = a { Some(i.as_str()) } else { None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win() -> LogSource {
        LogSource { category: Some("process_creation".into()), product: Some("Windows".into()), service: None }
    }

    fn built_in(name: &str) -> Pipeline {
        load(name, Path::new(".")).unwrap().0
    }

    #[test]
    fn built_ins_parse() {
        for (name, _) in BUILT_IN {
            assert!(!built_in(name).steps.is_empty(), "{name}");
        }
    }

    #[test]
    fn ecs_windows_maps_prefixes_and_conditions() {
        let p = [built_in("ecs_windows")];
        let r = Resolved::new(&p, &win(), "");
        assert_eq!(r.fields("Image"), vec!["process.executable"]);
        assert_eq!(r.fields("TargetUserName"), vec!["winlog.event_data.TargetUserName"]);
        let c = r.conditions();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0]["event.type"], "start");
        // Another logsource is left alone.
        let linux = LogSource { product: Some("linux".into()), ..LogSource::default() };
        let r = Resolved::new(&p, &linux, "");
        assert_eq!(r.fields("Image"), vec!["Image"]);
        assert!(r.conditions().is_empty());
    }

    #[test]
    fn sysmon_selects_event_ids() {
        let p = [built_in("sysmon")];
        let r = Resolved::new(&p, &win(), "");
        assert_eq!(r.fields("Image"), vec!["winlog.event_data.Image"]);
        assert_eq!(r.fields("EventID"), vec!["winlog.event_id"]);
        assert_eq!(r.conditions()[0]["winlog.event_id"], serde_json::json!([1]));
    }

    #[test]
    fn suffix_and_several_targets() {
        let p = [parse("transformations:\n  - {type: field_name_mapping, mapping: {A: [x, y], B: z}}\n  - {type: field_name_suffix, suffix: .raw, unmapped: true}\n").unwrap()];
        let r = Resolved::new(&p, &LogSource::default(), "");
        assert_eq!(r.fields("A"), vec!["x", "y"]);
        assert_eq!(r.fields("C"), vec!["C.raw"]);
        let r = Resolved::new(&p, &LogSource::default(), ".keyword");
        assert_eq!(r.fields("B"), vec!["z.keyword"]);
        assert_eq!(r.source_fields("B"), vec!["z"]);
    }

    #[test]
    fn set_index_and_logsource_conditions() {
        let p = [parse("transformations:\n  - {type: set_index, index: 'a-*'}\n  - {type: set_index, index: 'w-*', rule_conditions: [{type: logsource, product: windows, service: security}]}\n").unwrap()];
        assert_eq!(Resolved::new(&p, &win(), "").index(), Some("a-*"));
        let sec = LogSource { product: Some("windows".into()), service: Some("Security".into()), category: None };
        assert_eq!(Resolved::new(&p, &sec, "").index(), Some("w-*"));
    }

    #[test]
    fn refuses_what_it_cannot_apply() {
        for (y, want) in [
            ("transformations:\n  - {type: replace_string, regex: a, replacement: b}\n", "not supported"),
            ("transformations:\n  - {type: field_name_mapping, mapping: {A: b}, field_name_conditions: []}\n", "field_name_conditions"),
            ("transformations:\n  - {type: field_name_suffix, suffix: x, rule_conditions: [{type: contains_detection_item}]}\n", "only type logsource"),
            ("transformations:\n  - {type: field_name_mapping, mapping: {A: 3}}\n", "mapping of A"),
            ("postprocessing: []\ntransformations: []\n", "postprocessing"),
            ("name: x\n", "missing transformations"),
        ] {
            let err = format!("{:#}", parse(y).unwrap_err());
            assert!(err.contains(want), "{y}: {err}");
        }
        let err = load("nope", Path::new("/nonexistent")).unwrap_err().to_string();
        assert!(err.contains("ecs_windows") && err.contains("neither"));
    }
}
