//! Native Sigma rules. A rule file with `sigma: <path>` gets the detection of that Sigma file as a Query DSL `filter`; every
//! other option comes from the ElastAlert rule, which wins over anything derived from Sigma (the title, description, level,
//! ATT&CK tags and fields of the Sigma file fill in what the rule leaves unset). A Sigma correlation rule becomes the rule
//! type that counts or correlates (`corr.rs`), and Sigma filters are added to the rules they name.

mod condition;
mod corpus;
mod corr;
mod dsl;
mod modifiers;
mod pipeline;

pub use corpus::Corpus;

use crate::mitre::{self, Attack};
use anyhow::{Context, Result, bail};
use corpus::{Doc, Kind};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Keys a Sigma rule file may have. Anything else is refused: it may change the meaning of the rule.
const KNOWN_KEYS: &[&str] = &[
    "title", "id", "related", "name", "status", "description", "references", "author", "date", "modified", "tags", "logsource", "detection", "fields", "falsepositives",
    "level", "taxonomy", "license", "scope", "regression_tests_path", "simulation",
];

/// The Sigma file a rule points to, relative to the rule file.
fn path(raw: &Map<String, Value>) -> Option<PathBuf> {
    Some(base(raw).join(raw.get("sigma")?.as_str()?))
}

fn base(raw: &Map<String, Value>) -> &Path {
    raw.get("rule_file").and_then(Value::as_str).map(Path::new).and_then(Path::parent).unwrap_or(Path::new("."))
}

fn pipeline_specs(raw: &Map<String, Value>) -> Result<Vec<String>> {
    match raw.get("sigma_pipeline") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().map(String::from).context("sigma_pipeline must be a pipeline name, a file, or a list of them")).collect(),
        Some(_) => bail!("sigma_pipeline must be a pipeline name, a file, or a list of them"),
    }
}

/// `sigma_rules`: files and folders to look the rules a correlation refers to, and filters, up in.
fn sigma_rules(raw: &Map<String, Value>) -> Result<Vec<PathBuf>> {
    let list: Vec<&str> = match raw.get("sigma_rules") {
        None | Some(Value::Null) => vec![],
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().context("sigma_rules must be a list of files and folders")).collect::<Result<_>>()?,
        Some(_) => bail!("sigma_rules must be a list of files and folders"),
    };
    Ok(list.into_iter().map(|p| base(raw).join(p)).collect())
}

/// The documents a rule can refer to: its own file, `sigma_rules`, and the `sigma_folders`.
fn scope(own: Vec<std::sync::Arc<Doc>>, raw: &Map<String, Value>, global: &Corpus, lenient: bool) -> Result<Corpus> {
    let mut scope = Corpus::from_docs(own);
    let paths = sigma_rules(raw)?;
    if !paths.is_empty() {
        scope.extend(&Corpus::from_paths(&paths, lenient)?);
    }
    scope.extend(global);
    Ok(scope)
}

/// Files whose change must reload the rule: the Sigma file, the pipelines, the rules a correlation refers to, the
/// filters that apply.
pub fn files(raw: &Map<String, Value>, global: &Corpus) -> Vec<PathBuf> {
    let specs = pipeline_specs(raw).unwrap_or_default();
    let mut out: Vec<PathBuf> = path(raw).into_iter().chain(specs.iter().map(|s| base(raw).join(s)).filter(|f| f.is_file())).collect();
    if let Some(file) = path(raw)
        && let Ok(own) = corpus::read_docs(&file)
        && let Some(first) = own.first().cloned()
        && let Ok(scope) = scope(own, raw, global, true)
    {
        reach(&first, &scope, &mut out, 0);
    }
    out.sort();
    out.dedup();
    out
}

fn reach(doc: &Doc, scope: &Corpus, out: &mut Vec<PathBuf>, depth: usize) {
    out.push(doc.path.clone());
    match doc.kind {
        Kind::Detection => out.extend(scope.filters_for(doc).iter().map(|f| f.path.clone())),
        Kind::Correlation if depth < 8 => {
            for r in corr::references(doc) {
                if let Some(d) = scope.lookup(&r) {
                    reach(d, scope, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

/// Everything compiling a detection rule needs besides the rule.
struct Ctx<'a> {
    pipelines: &'a [pipeline::Pipeline],
    suffix: &'a str,
    keyword_fields: &'a [String],
    scope: &'a Corpus,
}

/// A detection rule compiled: its query, with the filters that name it, the index and fields its pipelines ask for.
struct Built<'a> {
    query: Value,
    index: Option<String>,
    include: Vec<String>,
    pipe: pipeline::Resolved<'a>,
}

fn build<'a>(rule: &Doc, ctx: &Ctx<'a>) -> Result<Built<'a>> {
    if let Some(k) = rule.map.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str())) {
        bail!("option {k} is not supported");
    }
    let Some(Value::Object(det)) = rule.map.get("detection") else { bail!("missing detection") };
    let source = pipeline::LogSource::from_rule(&rule.map)?;
    let pipe = pipeline::Resolved::new(ctx.pipelines, &source, ctx.suffix);
    let env = dsl::Env { keyword_fields: ctx.keyword_fields, pipe: &pipe };
    let mut parts = Vec::new();
    for cond in pipe.conditions() {
        for (field, v) in cond {
            parts.push(dsl::condition_clause(field, v).with_context(|| format!("pipeline condition {field}"))?);
        }
    }
    parts.push(dsl::detection(det, &env)?);
    for f in ctx.scope.filters_for(rule) {
        let Some(Value::Object(fm)) = f.map.get("filter") else { bail!("filter {}: filter must be a map", f.label()) };
        let mut fdet = fm.clone();
        fdet.remove("rules");
        let q = dsl::detection(&fdet, &env).with_context(|| format!("filter {}", f.label()))?;
        parts.push(dsl::not(q));
    }
    let mut include: Vec<String> = Vec::new();
    match rule.map.get("fields") {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for f in a {
                let Some(f) = f.as_str() else { bail!("fields must be a list of field names") };
                for name in pipe.source_fields(f) {
                    if !include.contains(&name) {
                        include.push(name);
                    }
                }
            }
        }
        Some(_) => bail!("fields must be a list of field names"),
    }
    Ok(Built { query: dsl::and(parts), index: pipe.index().map(String::from), include, pipe })
}

/// A Sigma selection (`field|modifier: value` map, or a list of maps) as a query, with the field names as written.
pub fn selection(sel: &Value) -> Result<Value> {
    let pipe = pipeline::Resolved::new(&[], &pipeline::LogSource::default(), "");
    let env = dsl::Env { keyword_fields: &[], pipe: &pipe };
    let det: Map<String, Value> = [("s".to_string(), sel.clone()), ("condition".to_string(), "s".into())].into_iter().collect();
    dsl::detection(&det, &env)
}

/// Adds a query to the `filter` of the rule, after the filters it has itself.
fn push_filter(raw: &mut Map<String, Value>, query: Value) -> Result<()> {
    let mut filter = match raw.remove("filter") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a,
        Some(_) => bail!("filter must be a list"),
    };
    if filter.iter().any(|f| f.get("eql").is_some() || f.get("esql").is_some()) {
        bail!("a sigma rule cannot also use an eql or esql filter");
    }
    filter.push(query);
    raw.insert("filter".into(), Value::Array(filter));
    Ok(())
}

/// Compiles the Sigma rule of `sigma:` into the options of the rule: the detection as a `filter` and `type: any`, or a
/// correlation as the rule type that counts it. `global` holds the documents of the `sigma_folders`.
pub fn apply(raw: &mut Map<String, Value>, attack: &Attack, global: &Corpus) -> Result<()> {
    match raw.get("sigma") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(_)) => {}
        Some(_) => bail!("sigma must be the path of a Sigma rule file"),
    }
    let file = path(raw).context("sigma")?;
    let from_folder = raw.remove("sigma_in_folder").is_some();
    let pipelines: Vec<pipeline::Pipeline> = pipeline_specs(raw)?.iter().map(|s| pipeline::load(s, base(raw)).map(|(p, _)| p)).collect::<Result<_>>()?;
    let suffix = match raw.get("sigma_keyword_suffix") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => bail!("sigma_keyword_suffix must be a string like .keyword"),
    };
    let keyword_fields = keyword_fields(raw)?;
    let here = || format!("Sigma rule {}", file.display());
    let own = corpus::read_docs(&file).with_context(here)?;
    let Some(first) = own.first().cloned() else { bail!("{}: no Sigma rule in the file", file.display()) };
    let scope = scope(own, raw, global, false).with_context(here)?;
    let ctx = Ctx { pipelines: &pipelines, suffix: &suffix, keyword_fields: &keyword_fields, scope: &scope };
    let name = raw.get("name").and_then(Value::as_str).or_else(|| file.file_stem().and_then(|s| s.to_str())).unwrap_or("rule").to_string();
    match first.kind {
        Kind::Detection => {
            let built = build(&first, &ctx).with_context(here)?;
            push_filter(raw, built.query)?;
            raw.entry("type").or_insert_with(|| "any".into());
            if let Some(i) = built.index {
                raw.entry("index").or_insert_with(|| i.into());
            }
            if !built.include.is_empty() {
                raw.entry("include").or_insert_with(|| built.include.into());
            }
        }
        Kind::Correlation => corr::apply(raw, &first, &ctx, from_folder).with_context(here)?,
        Kind::Filter => bail!("{} is a Sigma filter, not a rule: it applies to the rules it names, put it where they can find it (sigma_folders or sigma_rules)", file.display()),
        Kind::Other => bail!("{} is not a Sigma rule: it has no detection or correlation", file.display()),
    }
    meta(raw, &first.map, attack, &name)
}

/// A file of the `sigma_folders` that is not a rule of its own: a meta filter, or a detection rule a correlation refers to
/// (`generate: false`, the default) when `runs` says that correlation loads.
pub fn is_support_file(file: &Path, global: &Corpus, referenced: &[String]) -> bool {
    let docs: Vec<&std::sync::Arc<Doc>> = global.docs().iter().filter(|d| d.path == file).collect();
    match docs.first() {
        Some(d) if d.kind == Kind::Filter => true,
        Some(d) if d.kind == Kind::Detection => referenced.iter().any(|r| d.is(r)),
        _ => false,
    }
}

/// The references of the correlation rules of `global` that `runs` accepts, which do not generate their own alerts.
pub fn referenced_rules(global: &Corpus, mut runs: impl FnMut(&Path) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    for d in global.docs().iter().filter(|d| d.kind == Kind::Correlation) {
        let generate = d.map.get("correlation").and_then(|c| c.get("generate")).or_else(|| d.map.get("generate")).and_then(Value::as_bool).unwrap_or(false);
        if !generate && runs(&d.path) {
            out.extend(corr::references(d));
        }
    }
    out
}

const STATUSES: &[&str] = &["stable", "test", "experimental", "deprecated", "unsupported"];
/// Sigma `level`, and the `priority` it gives a rule (lower is more severe, like the P1 to P5 of Opsgenie).
const LEVELS: &[(&str, u8)] = &[("critical", 1), ("high", 2), ("medium", 3), ("low", 4), ("informational", 5)];

/// What the rule takes from the Sigma metadata when it sets none of its own: `alert_subject` (title), `description`,
/// `priority` (level) and `mitre_attack` (the `attack.tNNNN` tags).
fn meta(raw: &mut Map<String, Value>, sigma: &Map<String, Value>, attack: &Attack, name: &str) -> Result<()> {
    let text = |k: &str| -> Result<Option<&str>> {
        match sigma.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.as_str())),
            Some(_) => bail!("{k} must be a string"),
        }
    };
    if let Some(s) = text("status")? {
        if !STATUSES.contains(&s) {
            bail!("status {s:?} is not a Sigma status ({})", STATUSES.join(", "));
        }
        if s == "deprecated" {
            log::warn!("Rule {name}: the Sigma rule is deprecated");
        }
    }
    if let Some(l) = text("level")? {
        let Some((_, p)) = LEVELS.iter().find(|(n, _)| *n == l) else {
            bail!("level {l:?} is not a Sigma level ({})", LEVELS.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", "));
        };
        raw.entry("priority").or_insert_with(|| (*p).into());
        // Entities named without a score get one from the level (informational gets none: say it with risk_score).
        if raw.contains_key("risk_objects") && let Some(score) = [("low", 25), ("medium", 50), ("high", 75), ("critical", 100)].iter().find(|(n, _)| *n == l).map(|(_, s)| *s) {
            raw.entry("risk_score").or_insert_with(|| score.into());
        }
    }
    if let Some(t) = text("title")? {
        raw.entry("alert_subject").or_insert_with(|| t.into());
    }
    if let Some(d) = text("description")? {
        raw.entry("description").or_insert_with(|| d.into());
    }
    if !raw.contains_key("mitre_attack") {
        let tags = match sigma.get("tags") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            Some(_) => bail!("tags must be a list"),
        };
        let mut ids: Vec<String> = Vec::new();
        for id in tags.iter().filter_map(|t| t.to_ascii_lowercase().strip_prefix("attack.").map(str::to_ascii_uppercase)) {
            if !mitre::is_technique_id(&id) || ids.contains(&id) {
                continue; // tactics, groups and software tags
            }
            if attack.get(&id).is_some() {
                ids.push(id);
            } else {
                log::warn!("Rule {name}: Sigma tag attack.{} is not a technique of Enterprise ATT&CK {}, ignored", id.to_ascii_lowercase(), attack.version);
            }
        }
        if !ids.is_empty() {
            raw.insert("mitre_attack".into(), ids.into());
        }
    }
    Ok(())
}

fn keyword_fields(raw: &Map<String, Value>) -> Result<Vec<String>> {
    match raw.get("sigma_keyword_fields") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().map(String::from).context("sigma_keyword_fields must be a list of field names")).collect(),
        Some(_) => bail!("sigma_keyword_fields must be a list of field names"),
    }
}

#[derive(clap::Args)]
pub struct ConvertArgs {
    /// Sigma rule file
    file: PathBuf,
    /// Pipeline: a built-in name or a file; repeat to stack them (sigma_pipeline)
    #[arg(long, short = 'p')]
    pipeline: Vec<String>,
    /// Field for keyword searches; repeat for several (sigma_keyword_fields)
    #[arg(long = "keyword-field")]
    keyword_field: Vec<String>,
    /// Text added to every field name, e.g. .keyword (sigma_keyword_suffix)
    #[arg(long = "keyword-suffix")]
    keyword_suffix: Option<String>,
    /// Files and folders to look up the rules a correlation refers to, and filters (sigma_rules)
    #[arg(long = "rules")]
    rules: Vec<PathBuf>,
    /// Print only the search body {"query": ...}, to paste into Dev Tools or send with curl
    #[arg(long)]
    dsl: bool,
}

/// What a rule file with `sigma: <file>` and these options gets from the Sigma rule.
fn convert(a: &ConvertArgs, attack: &Attack) -> Result<Map<String, Value>> {
    let mut raw = Map::new();
    raw.insert("rule_file".into(), "./sigma-convert".into());
    raw.insert("sigma".into(), a.file.to_string_lossy().into_owned().into());
    raw.insert("sigma_pipeline".into(), a.pipeline.clone().into());
    raw.insert("sigma_keyword_fields".into(), a.keyword_field.clone().into());
    if let Some(s) = &a.keyword_suffix {
        raw.insert("sigma_keyword_suffix".into(), s.clone().into());
    }
    raw.insert("sigma_rules".into(), a.rules.iter().map(|p| p.to_string_lossy().into_owned()).collect::<Vec<_>>().into());
    apply(&mut raw, attack, &Corpus::default())?;
    let keys = [
        "type", "index", "filter", "alert_subject", "description", "priority", "mitre_attack", "include", "num_events", "timeframe", "query_key", "cardinality_field",
        "max_cardinality", "correlation_leaves", "correlation_query",
    ];
    Ok(keys.iter().filter_map(|k| raw.remove(*k).map(|v| (k.to_string(), v))).collect())
}

pub fn convert_cmd(a: &ConvertArgs) -> Result<()> {
    let mut out = convert(a, &Attack::embedded())?;
    if a.dsl {
        let Some(Value::Array(mut filter)) = out.remove("filter") else {
            bail!("this rule is a {} rule, which is not one search: print it without --dsl", out.get("type").and_then(Value::as_str).unwrap_or("?"))
        };
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"query": dsl::and(std::mem::take(&mut filter))}))?);
    } else {
        print!("{}", serde_yaml_ng::to_string(&out)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn raw(dir: &Path, wrapper: &str, sigma: &str) -> Map<String, Value> {
        std::fs::write(dir.join("s.yml"), sigma).unwrap();
        let Value::Object(mut m) = serde_yaml_ng::from_str::<Value>(wrapper).unwrap() else { panic!() };
        m.insert("rule_file".into(), json!(dir.join("w.yaml").to_string_lossy()));
        m
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ea3-sigma-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const RULE: &str = "title: t\nlogsource: {product: windows}\ndetection:\n  sel: {Image|endswith: '\\\\cmd.exe'}\n  condition: sel\nlevel: high\n";

    #[test]
    fn wrapper_gets_filter_and_default_type() {
        let d = tmp("apply");
        let mut r = raw(&d, "sigma: s.yml\nfilter:\n  - term: {host: a}\n", RULE);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["type"], "any");
        let f = r["filter"].as_array().unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0], json!({"term": {"host": "a"}}));
        assert!(f[1]["wildcard"]["Image"].is_object());
        let mut r = raw(&d, "sigma: s.yml\ntype: frequency\n", RULE);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["type"], "frequency");
        assert_eq!(files(&r, &Corpus::default()), vec![d.join("s.yml")]);
    }

    #[test]
    fn refuses_what_it_cannot_run() {
        let d = tmp("refuse");
        for (wrapper, sigma, want) in [
            ("sigma: s.yml\n", "title: t\ncorrelation: {type: event_count}\n", "rules is required"),
            ("sigma: s.yml\n", "title: t\n", "no detection or correlation"),
            ("sigma: missing.yml\n", RULE, "missing.yml"),
            ("sigma: [a]\n", RULE, "path"),
            ("sigma: s.yml\nfilter: [{eql: 'any where true'}]\n", RULE, "eql"),
            ("sigma: s.yml\nsigma_keyword_fields: 3\n", RULE, "sigma_keyword_fields"),
        ] {
            let mut r = raw(&d, wrapper, sigma);
            let err = format!("{:#}", apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap_err());
            assert!(err.contains(want), "{wrapper}: {err}");
        }
    }

    #[test]
    fn pipelines_map_fields_add_conditions_and_set_index() {
        let d = tmp("pipe");
        std::fs::write(d.join("p.yml"), "transformations:\n  - {type: set_index, index: 'win-*'}\n  - {type: field_name_suffix, suffix: .raw}\n").unwrap();
        let mut r = raw(&d, "sigma: s.yml\nsigma_pipeline: [ecs_windows, p.yml]\n", &RULE.replace("{product: windows}", "{product: windows, category: process_creation}"));
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["index"], "win-*");
        let q = r["filter"][0].to_string();
        assert!(q.contains("process.executable.raw") && q.contains("event.type"), "{q}");
        assert_eq!(files(&r, &Corpus::default()), vec![d.join("p.yml"), d.join("s.yml")]);
        // The rule's own index wins; a bad pipeline fails the load.
        let mut r = raw(&d, "sigma: s.yml\nsigma_pipeline: p.yml\nindex: mine\nsigma_keyword_suffix: .keyword\n", RULE);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["index"], "mine");
        assert!(r["filter"][0].to_string().contains("Image.raw.keyword"));
        let mut r = raw(&d, "sigma: s.yml\nsigma_pipeline: nope\n", RULE);
        assert!(format!("{:#}", apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap_err()).contains("neither a built-in"));
    }

    const META: &str = "title: Encoded PowerShell\ndescription: Spots -enc\nstatus: test\nlevel: high\ntags: [attack.execution, attack.t1059.001, attack.T1078, attack.t9999, attack.g0001]\nfields: [Image, CommandLine]\nlogsource: {product: windows}\ndetection:\n  sel: {Image|endswith: '\\\\cmd.exe'}\n  condition: sel\n";

    #[test]
    fn metadata_fills_in_what_the_rule_leaves_unset() {
        let d = tmp("meta");
        let mut r = raw(&d, "sigma: s.yml\nsigma_pipeline: ecs_windows\nsigma_keyword_suffix: .keyword\n", META);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["alert_subject"], "Encoded PowerShell");
        assert_eq!(r["description"], "Spots -enc");
        assert_eq!(r["priority"], 2);
        // Unknown techniques (t9999) are skipped, tactics and groups are not techniques.
        assert_eq!(r["mitre_attack"], json!(["T1059.001", "T1078"]));
        // include names the stored fields: renamed by the pipeline, without the keyword suffix.
        assert_eq!(r["include"], json!(["process.executable", "process.command_line"]));
        // Whatever the rule sets itself wins.
        let own = "sigma: s.yml\nalert_subject: Mine\ndescription: d\npriority: 4\nmitre_attack: T1078\ninclude: [host]\n";
        let mut r = raw(&d, own, META);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!((&r["alert_subject"], &r["description"], &r["priority"], &r["mitre_attack"], &r["include"]), (&json!("Mine"), &json!("d"), &json!(4), &json!("T1078"), &json!(["host"])));
    }

    #[test]
    fn risk_objects_get_a_score_from_the_level() {
        let d = tmp("risk");
        let mut r = raw(&d, "sigma: s.yml\nrisk_objects: {host: host.name}\n", META); // level: high
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["risk_score"], 75);
        let mut r = raw(&d, "sigma: s.yml\nrisk_objects: {host: host.name}\nrisk_score: 10\n", META);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r["risk_score"], 10);
        let mut r = raw(&d, "sigma: s.yml\n", META);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert!(!r.contains_key("risk_score"));
    }

    #[test]
    fn refuses_unknown_status_and_level() {
        let d = tmp("badmeta");
        for (sigma, want) in [(META.replace("status: test", "status: maybe"), "not a Sigma status"), (META.replace("level: high", "level: urgent"), "not a Sigma level"), (META.replace("fields: [Image, CommandLine]", "fields: Image"), "fields")] {
            let mut r = raw(&d, "sigma: s.yml\n", &sigma);
            let err = format!("{:#}", apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap_err());
            assert!(err.contains(want), "{err}");
        }
    }

    #[test]
    fn convert_prints_the_derived_options() {
        let d = tmp("convert");
        std::fs::write(d.join("s.yml"), META).unwrap();
        let args = ConvertArgs { file: d.join("s.yml"), pipeline: vec!["ecs_windows".into()], keyword_field: vec![], keyword_suffix: None, rules: vec![], dsl: false };
        let out = convert(&args, &Attack::embedded()).unwrap();
        assert_eq!(out["type"], "any");
        assert_eq!(out["priority"], 2);
        assert_eq!(out["include"], json!(["process.executable", "process.command_line"]));
        assert!(out["filter"][0]["wildcard"]["process.executable"].is_object());
        assert!(!out.contains_key("index"));
        let err = format!("{:#}", convert(&ConvertArgs { file: d.join("nope.yml"), ..args }, &Attack::embedded()).unwrap_err());
        assert!(err.contains("nope.yml"), "{err}");
    }

    const FLAGSHIP: &str = "title: Failed logins then success\nlevel: high\ncorrelation:\n  type: temporal_ordered\n  rules: [multiple_failed_login, successful_login]\n  group-by: [User]\n  timespan: 10m\n---\ntitle: Multiple failed logons\nname: multiple_failed_login\ncorrelation:\n  type: event_count\n  rules: [failed_login]\n  group-by: [User]\n  timespan: 10m\n  condition: {gte: 10}\n---\ntitle: Single failed login\nname: failed_login\nlogsource: {product: windows}\ndetection:\n  selection: {EventID: [529, 4625]}\n  condition: selection\n---\ntitle: Successful login\nname: successful_login\nlogsource: {product: windows}\ndetection:\n  selection: {EventID: [528, 4624]}\n  condition: selection\n";

    fn applied(dir: &Path, wrapper: &str, sigma: &str) -> Result<Map<String, Value>> {
        let mut r = raw(dir, wrapper, sigma);
        apply(&mut r, &Attack::embedded(), &Corpus::default()).map(|_| r)
    }

    #[test]
    fn temporal_ordered_with_an_event_count_leaf() {
        let d = tmp("flagship");
        let r = applied(&d, "sigma: s.yml\nindex: logs-*\n", FLAGSHIP).unwrap();
        assert_eq!((r["type"].as_str(), r["query_key"].as_str(), r["priority"].as_u64()), (Some("correlation"), Some("User"), Some(2)));
        assert_eq!(r["timeframe"], json!({"minutes": 10}));
        assert_eq!(r["correlation_query"], "multiple_failed_login THEN successful_login");
        assert_eq!(r["correlation_leaves"]["multiple_failed_login"]["num_events"], 10);
        assert_eq!(r["correlation_leaves"]["successful_login"]["num_events"], 1);
        assert!(r["correlation_leaves"]["successful_login"]["filter"][0].to_string().contains("4624"));
        assert!(!r.contains_key("filter"));
    }

    #[test]
    fn event_count_value_count_and_temporal() {
        let d = tmp("types");
        let det = "---\nname: a\nlogsource: {product: windows}\ndetection: {s: {X: 1}, condition: s}\n---\nname: b\nlogsource: {product: windows}\ndetection: {s: {Y: 2}, condition: s}\n";
        let r = applied(&d, "sigma: s.yml\nindex: i\nfilter: [{term: {host: h}}]\n", &format!("title: t\ncorrelation: {{type: event_count, rules: [a, b], group-by: [U], timespan: 30s, condition: {{gt: 99}}}}\n{det}")).unwrap();
        assert_eq!((r["type"].as_str(), r["num_events"].as_u64(), r["query_key"].as_str()), (Some("frequency"), Some(100), Some("U")));
        assert_eq!(r["timeframe"], json!({"seconds": 30}));
        assert_eq!(r["filter"].as_array().unwrap().len(), 2);
        assert_eq!(r["filter"][0], json!({"term": {"host": "h"}}));
        assert_eq!(r["filter"][1]["bool"]["should"].as_array().unwrap().len(), 2);

        let r = applied(&d, "sigma: s.yml\nindex: i\n", &format!("title: t\ncorrelation: {{type: value_count, rules: [a], group-by: [Src], timespan: 1h, condition: {{field: User, gte: 5}}}}\n{det}")).unwrap();
        assert_eq!((r["type"].as_str(), r["cardinality_field"].as_str(), r["max_cardinality"].as_u64()), (Some("cardinality"), Some("User"), Some(4)));

        // Aliases name the group-by field per rule: a leaf reads the pivot from its own field.
        let r = applied(&d, "sigma: s.yml\nindex: i\n", &format!("title: t\ncorrelation: {{type: temporal, rules: [a, b], group-by: [ip], timespan: 5m, aliases: {{ip: {{a: Src, b: Dst}}}}}}\n{det}")).unwrap();
        assert_eq!((r["query_key"].as_str(), r["correlation_query"].as_str()), (Some("Src"), Some("a AND b")));
        assert_eq!(r["correlation_leaves"]["b"]["query_key"], "Dst");
        assert!(r["correlation_leaves"]["a"].get("query_key").is_none());
    }

    #[test]
    fn pipelines_and_indices_reach_correlation_leaves() {
        let d = tmp("leaf-pipe");
        std::fs::write(d.join("p.yml"), "transformations:\n  - {type: field_name_mapping, mapping: {User: user.name}}\n  - {type: set_index, index: 'win-*'}\n").unwrap();
        let r = applied(&d, "sigma: s.yml\nsigma_pipeline: p.yml\n", FLAGSHIP).unwrap();
        assert_eq!(r["query_key"], "user.name");
        assert_eq!(r["index"], "win-*");
        assert_eq!(r["correlation_leaves"]["successful_login"]["index"], "win-*");
    }

    #[test]
    fn correlation_refusals() {
        let d = tmp("corr-refuse");
        let det = "---\nname: a\nlogsource: {product: windows}\ndetection: {s: {X: 1}, condition: s}\n---\nname: b\nlogsource: {product: windows}\ndetection: {s: {Y: 2}, condition: s}\n";
        let corr = |c: &str| format!("title: t\ncorrelation: {{{c}}}\n{det}");
        for (wrapper, sigma, want) in [
            ("sigma: s.yml\n", corr("type: value_sum, rules: [a], group-by: [U], timespan: 1h, condition: {field: B, gt: 1}"), "value_sum is not supported"),
            ("sigma: s.yml\n", corr("type: event_count, rules: [a], group-by: [U], timespan: 1h, condition: {lt: 3}"), "lt is not supported"),
            ("sigma: s.yml\n", corr("type: event_count, rules: [a], group-by: [U], timespan: 1h, condition: {gt: 1, lte: 5}"), "exactly one"),
            ("sigma: s.yml\n", corr("type: event_count, rules: [zzz], group-by: [U], timespan: 1h, condition: {gte: 3}"), "\"zzz\" is not in this file"),
            ("sigma: s.yml\n", corr("type: event_count, rules: [a], group-by: [U], timespan: 1h, condition: {gte: 3}, generate: true"), "generate: true"),
            ("sigma: s.yml\ntimeframe: {minutes: 1}\n", corr("type: event_count, rules: [a], group-by: [U], timespan: 1h, condition: {gte: 3}"), "timeframe comes from"),
            ("sigma: s.yml\n", corr("type: temporal, rules: [a, b], timespan: 1h"), "group-by is required"),
            ("sigma: s.yml\n", corr("type: temporal, rules: [a], group-by: [U], timespan: 1h"), "at least two rules"),
            ("sigma: s.yml\n", corr("type: temporal, rules: [a, b], group-by: [U], timespan: 1h, condition: {gte: 1}"), "not all 2 rules"),
            ("sigma: s.yml\n", corr("type: temporal, rules: [a, b], group-by: [U], timespan: 1h, aliases: {U: [x]}"), "aliases"),
            ("sigma: s.yml\n", corr("type: temporal, rules: [a, b], group-by: [U, V], timespan: 1h, aliases: {U: {a: P, b: Q}}"), "different names"),
            ("sigma: s.yml\n", corr("type: nonsense, rules: [a], group-by: [U], timespan: 1h"), "not a Sigma correlation type"),
        ] {
            let err = format!("{:#}", applied(&d, wrapper, &sigma).unwrap_err());
            assert!(err.contains(want), "{want}: {err}");
        }
        let named = "title: t\nname: corr\ncorrelation: {type: event_count, rules: [a], group-by: [U], timespan: 1h, condition: {gte: 3}}\n---\nname: a\nlogsource: {product: windows}\ndetection: {s: {X: 1}, condition: s}\n---\ntitle: f\nfilter: {rules: [corr], selection: {Z: 1}, condition: selection}\n";
        assert!(format!("{:#}", applied(&d, "sigma: s.yml\n", named).unwrap_err()).contains("names this correlation"));
        // A leaf that is a correlation must be an event_count with the same timespan and group-by.
        let inner = "group-by: [User]\n  timespan: 10m\n  condition: {gte: 10}";
        for patch in ["group-by: [User]\n  timespan: 5m\n  condition: {gte: 10}", "group-by: [Other]\n  timespan: 10m\n  condition: {gte: 10}"] {
            let err = format!("{:#}", applied(&d, "sigma: s.yml\nindex: i\n", &FLAGSHIP.replacen(inner, patch, 1)).unwrap_err());
            assert!(err.contains("must equal") || err.contains("groups by"), "{err}");
        }
    }

    #[test]
    fn filters_exclude_matches_of_the_rules_they_name() {
        let d = tmp("filters");
        let rule = "title: r\nname: proc\nid: 6f3e2987\nlogsource: {product: windows}\ndetection: {s: {Image|endswith: '\\\\a.exe'}, condition: s}\n";
        let filter = "---\ntitle: admins\nfilter:\n  rules: [6f3e2987]\n  selection: {User|startswith: 'adm_'}\n  condition: selection\n---\ntitle: other\nfilter:\n  rules: [someone_else]\n  selection: {Z: 1}\n  condition: selection\n";
        let r = applied(&d, "sigma: s.yml\n", &format!("{rule}{filter}")).unwrap();
        let q = r["filter"][0].to_string();
        assert!(q.contains("must_not") && q.contains("adm_*") && !q.contains("\"Z\""), "{q}");
        // The filter can live in another file, found through sigma_rules or the corpus of the sigma_folders.
        std::fs::create_dir_all(d.join("filters")).unwrap();
        std::fs::write(d.join("filters/f.yml"), filter.trim_start_matches("---\n")).unwrap();
        let r = applied(&d, "sigma: s.yml\nsigma_rules: [filters]\n", rule).unwrap();
        assert!(r["filter"][0].to_string().contains("adm_*"));
        let mut raw2 = raw(&d, "sigma: s.yml\nsigma_rules: [filters]\n", rule);
        assert_eq!(files(&raw2, &Corpus::default()), vec![d.join("filters/f.yml"), d.join("s.yml")]);
        raw2.remove("sigma_rules");
        let r = applied(&d, "sigma: s.yml\n", rule).unwrap();
        assert!(!r["filter"][0].to_string().contains("must_not"));
        // A filter is not a rule.
        let err = format!("{:#}", applied(&d, "sigma: filters/f.yml\n", "unused: 1\n").unwrap_err());
        assert!(err.contains("is a Sigma filter"), "{err}");
    }

    #[test]
    fn correlation_files_list_the_rules_they_refer_to() {
        let d = tmp("corr-files");
        std::fs::create_dir_all(d.join("base")).unwrap();
        std::fs::write(d.join("base/failed.yml"), "title: f\nname: failed_login\nlogsource: {product: windows}\ndetection: {s: {X: 1}, condition: s}\n").unwrap();
        let top = "title: t\ncorrelation: {type: event_count, rules: [failed_login], group-by: [U], timespan: 1m, condition: {gte: 2}}\n";
        let r = applied(&d, "sigma: s.yml\nindex: i\nsigma_rules: base\n", top).unwrap();
        assert_eq!(r["type"], "frequency");
        let raw3 = raw(&d, "sigma: s.yml\nindex: i\nsigma_rules: base\n", top);
        assert_eq!(files(&raw3, &Corpus::default()), vec![d.join("base/failed.yml"), d.join("s.yml")]);
    }

    #[test]
    fn rules_without_sigma_are_untouched() {
        let mut r = serde_yaml_ng::from_str::<Map<String, Value>>("type: any\n").unwrap();
        let before = r.clone();
        apply(&mut r, &Attack::embedded(), &Corpus::default()).unwrap();
        assert_eq!(r, before);
    }
}
