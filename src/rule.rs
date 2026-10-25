//! Rule files: discovery, `import:` chains, defaults inherited from config.yaml, validation.

use crate::config::{Config, read_yaml};
use crate::enhancements::{self, Enhancement};
use crate::querylang::{self, QueryLang};
use crate::time::{Dur, MINUTE, SECOND, parse_duration_map};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Any,
    Frequency,
    Spike,
    Flatline,
    Blacklist,
    Whitelist,
    Change,
    NewTerm,
    Cardinality,
    MetricAggregation,
    PercentageMatch,
    SpikeAggregation,
    Correlation,
}

impl Kind {
    /// Types answered by one aggregation query per segment instead of by hits.
    pub fn is_agg_query(self) -> bool {
        matches!(self, Kind::MetricAggregation | Kind::PercentageMatch | Kind::SpikeAggregation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TsType {
    Iso,
    Unix,
    UnixMs,
}

/// One leaf of a `correlation` rule: the events it stands for, as its own search.
#[derive(Clone, Debug)]
pub struct Leaf {
    pub name: String,
    pub filter: Vec<Value>,
    /// Overrides the rule's `index` for this leaf.
    pub index: Option<String>,
    /// Field holding the pivot value in this leaf's documents, when it differs from the rule's `query_key`.
    pub query_key: Option<String>,
    pub num_events: u64,
}

/// `correlation_leaves` + `correlation_query` of a `correlation` rule.
#[derive(Clone, Debug)]
pub struct CorrelationSpec {
    pub leaves: Vec<Leaf>,
    pub query: crate::correlation::Query,
}

/// When an aggregated alert is sent after its first match.
#[derive(Clone, Debug)]
pub enum Aggregation {
    Timespan(Dur),
    Cron(String),
}

#[derive(Clone)]
pub struct Rule {
    pub name: String,
    pub file: PathBuf,
    pub kind: Kind,
    pub index: String,
    pub filter: Vec<Value>,
    pub timestamp_field: String,
    pub timestamp_type: TsType,
    pub use_local_time: bool,
    pub query_key: Option<String>,
    pub compound_query_key: Vec<String>,
    pub realert: Dur,
    pub realert_key: String,
    pub buffer_time: Dur,
    pub run_every: Dur,
    pub query_delay: Dur,
    pub timeframe: Option<Dur>,
    pub num_events: u64,
    pub attach_related: bool,
    pub compare_key: Vec<String>,
    pub use_strftime_index: bool,
    pub search_extra_index: bool,
    /// Fields requested from ES (`_source.includes`).
    pub include: Vec<String>,
    /// True when only a projection is fetched and matches get their full document via `_mget`.
    pub enrich: bool,
    pub scan_entire_timeframe: bool,
    pub aggregation: Option<Aggregation>,
    pub aggregation_key: Option<String>,
    pub compound_aggregation_key: Vec<String>,
    pub use_count_query: bool,
    pub use_terms_query: bool,
    pub terms_size: u64,
    /// Fields for the "top events" counts, with the keyword suffix already applied.
    pub top_count_keys: Vec<String>,
    pub top_count_number: u64,
    /// Field set by the ingest pipeline; when present, queries use it instead of the event time.
    pub ingest_field: Option<String>,
    pub exponential_realert: Option<Dur>,
    pub query_timezone: Option<chrono_tz::Tz>,
    pub allow_degraded: bool,
    /// `read_doc_values`: the fetched fields are read from doc values instead of `_source` when the mapping allows.
    pub read_doc_values: bool,
    /// `split_on_limit`: an EQL / ES|QL range that returns `max_query_size` results is cut in two and read as two.
    pub split_on_limit: bool,
    /// `search_timeout`: Elasticsearch gives up a search after this long; a partial result is an error.
    pub search_timeout: Option<Dur>,
    /// `terminate_after`: documents collected per shard before a hit search stops early.
    pub terminate_after: Option<u64>,
    /// `preference` and `routing` as URL parameters (`&preference=x&routing=y`), empty when neither is set.
    pub search_params: String,
    pub include_fields: Option<Vec<String>>,
    pub jinja_template: Option<String>,
    pub max_query_size: u64,
    pub max_scrolling_count: u64,
    /// metric_aggregation / percentage_match / spike_aggregation: the aggregation sub-tree to run.
    pub agg_query: Option<Value>,
    /// `bucket_interval` as an Elasticsearch `fixed_interval` (`5m`) and in microseconds.
    pub bucket_interval: Option<(String, Dur)>,
    pub use_run_every_query_size: bool,
    pub sync_bucket_interval: bool,
    pub allow_buffer_time_overlap: bool,
    pub alerts: Vec<String>,
    /// Per-alerter options of `alert: [{slack: {slack_webhook_url: ...}}]`, parallel to `alerts` (`None` for a plain name).
    pub alert_configs: Vec<Option<Map<String, Value>>>,
    /// `limit_execution`: cron expression of the periods the rule is active in.
    pub limit_execution: Option<String>,
    /// `limit_execution_coverage`: do not catch up on the time skipped between two active periods.
    pub limit_execution_coverage: bool,
    /// `active_hours` (extension): matches whose timestamp falls outside these windows are ignored.
    pub active_hours: Option<crate::hours::ActiveHours>,
    pub kibana_discover: bool,
    pub opensearch_discover: bool,
    pub enhancements: Vec<std::sync::Arc<dyn Enhancement>>,
    pub run_enhancements_first: bool,
    /// Set when a `filter` entry is an `eql` or `esql` query.
    pub query_lang: Option<QueryLang>,
    /// `correlation` rules: the leaves to correlate on `query_key`, and how.
    pub correlation: Option<CorrelationSpec>,
    /// `mitre_attack` (extension): the ATT&CK techniques the rule detects, checked against the ATT&CK table.
    pub mitre_attack: Vec<crate::mitre::Technique>,
    /// The merged rule document; alert text and alerters read arbitrary keys from it.
    pub raw: Map<String, Value>,
}

/// The Jinja source of `alert_text` (or `jinja_template_path`) when `alert_text_type` is `alert_text_jinja`.
fn jinja_template_of(raw: &Map<String, Value>) -> Result<Option<String>> {
    if raw.get("alert_text_type").and_then(Value::as_str) != Some("alert_text_jinja") {
        return Ok(None);
    }
    let src = match raw.get("jinja_template_path").and_then(Value::as_str) {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading jinja_template_path {p}"))?,
        None => raw.get("alert_text").and_then(Value::as_str).unwrap_or("").to_string(),
    };
    crate::alert::check_jinja(&src).map_err(|e| anyhow::anyhow!("invalid jinja template: {e}"))?;
    Ok(Some(src))
}

/// One element of `alert:`: `name`, or `{name: {option: value, ...}}`.
fn alert_entry(x: &Value) -> Result<(String, Option<Map<String, Value>>)> {
    match x {
        Value::String(s) => Ok((s.clone(), None)),
        Value::Object(m) if m.len() == 1 => {
            let (name, config) = m.iter().next().expect("one entry");
            match config {
                Value::Object(c) => Ok((name.clone(), Some(c.clone()))),
                _ => bail!("the options of the alert {name} must be a map"),
            }
        }
        Value::Object(_) => bail!("an alert entry must be a name or a map with one alert name"),
        _ => bail!("alert entries must be names or maps like {{slack: {{slack_webhook_url: ...}}}}"),
    }
}

impl Rule {
    /// The rule as the alerter at position `i` sees it: the options of its `alert:` entry laid over the rule's own
    /// (upstream's `normalize_config`). Only alert options and alert text are meant to change this way: query and
    /// rule type options are read once, from the rule itself.
    pub fn with_alert_config(&self, config: &Map<String, Value>) -> Result<Rule> {
        let mut r = self.clone();
        r.raw.extend(config.clone());
        resolve_refs(&mut r.raw);
        if let Some(name) = r.raw.get("name").and_then(Value::as_str) {
            r.name = name.to_string();
        }
        r.jinja_template = jinja_template_of(&r.raw)?;
        Ok(r)
    }

    /// What `alerters_sent` stores for each alerter: its name, and `name#2`, `name#3` ... for repeats of the same alerter.
    pub fn alert_labels(&self) -> Vec<String> {
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        self.alerts
            .iter()
            .map(|a| {
                let n = seen.entry(a.as_str()).or_insert(0);
                *n += 1;
                if *n == 1 { a.clone() } else { format!("{a}#{n}") }
            })
            .collect()
    }
}

pub fn is_yaml(p: &Path) -> bool {
    matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml"))
}

fn walk(dir: &Path, recurse: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading rules folder {}", dir.display()))? {
        let path = entry?.path();
        let hidden_k8s = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(".."));
        if path.is_dir() {
            if recurse && !hidden_k8s {
                walk(&path, recurse, out)?;
            }
        } else if is_yaml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Rule files to load. `--rule` may be a path or a bare file name inside the rules folders.
pub fn discover(conf: &Config, only: Option<&str>) -> Result<Vec<PathBuf>> {
    if let Some(r) = only.map(Path::new).filter(|p| p.is_file()) {
        return Ok(vec![r.to_path_buf()]);
    }
    let mut files = Vec::new();
    for dir in &conf.rules_folders {
        if !dir.exists() {
            // A setup made of Sigma folders alone has no use for the default rules folder.
            if !conf.sigma_folders.is_empty() {
                continue;
            }
            bail!("rules folder does not exist: {}", dir.display());
        }
        walk(dir, conf.scan_subdirectories, &mut files)?;
    }
    if !conf.sigma_folders.is_empty() {
        // One read of the Sigma folders per scan: the rules, the filters and the correlations are looked up in it.
        *conf.sigma_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let mut sigma_files = Vec::new();
        for dir in &conf.sigma_folders {
            if !dir.exists() {
                bail!("sigma folder does not exist: {}", dir.display());
            }
            walk(dir, true, &mut sigma_files)?;
        }
        let global = sigma_corpus(conf);
        // Filters, and the rules a correlation refers to (unless it generates them), are not rules of their own.
        let referenced = crate::sigma::referenced_rules(&global, |p| correlation_loads(p, conf));
        files.extend(sigma_files.into_iter().filter(|f| !crate::sigma::is_support_file(f, &global, &referenced)));
    }
    if let Some(name) = only {
        files.retain(|f| f.file_name().and_then(|n| n.to_str()) == Some(name));
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// The Sigma documents of the `sigma_folders`.
fn sigma_corpus(conf: &Config) -> Arc<crate::sigma::Corpus> {
    let mut slot = conf.sigma_cache.lock().unwrap_or_else(|e| e.into_inner());
    slot.get_or_insert_with(|| Arc::new(crate::sigma::Corpus::from_paths(&conf.sigma_folders, true).unwrap_or_default())).clone()
}

/// Whether a correlation rule of the `sigma_folders` compiles; only then do the rules it refers to stop running on their own.
fn correlation_loads(file: &Path, conf: &Config) -> bool {
    let Ok((mut raw, _)) = read_rule(file, conf) else { return false };
    for (k, v) in &conf.raw {
        raw.entry(k.clone()).or_insert_with(|| v.clone());
    }
    crate::sigma::apply(&mut raw, &conf.attack, &sigma_corpus(conf)).is_ok()
}

/// A plain Sigma file inside one of the `sigma_folders`.
fn is_sigma_file(file: &Path, conf: &Config) -> bool {
    if conf.sigma_folders.is_empty() {
        return false;
    }
    let Ok(file) = file.canonicalize() else { return false };
    conf.sigma_folders.iter().any(|d| d.canonicalize().is_ok_and(|d| file.starts_with(d)))
}

/// The options of a rule file before defaults and Sigma are applied: the file itself, or for a plain Sigma file the
/// `sigma_defaults` pointing at it.
fn read_rule(file: &Path, conf: &Config) -> Result<(Map<String, Value>, Vec<PathBuf>)> {
    if !is_sigma_file(file, conf) {
        return load_yaml(file);
    }
    if !conf.sigma_defaults.contains_key("alert") && !conf.raw.contains_key("alert") {
        bail!("rules from sigma_folders need an alert: set one in sigma_defaults");
    }
    let mut raw = conf.sigma_defaults.clone();
    raw.insert("rule_file".into(), json!(file.to_string_lossy()));
    raw.insert("sigma".into(), json!(file.file_name().and_then(|n| n.to_str()).unwrap_or_default()));
    raw.insert("sigma_in_folder".into(), json!(true));
    Ok((raw, vec![file.to_path_buf()]))
}

/// Reads a rule and its `import:` chain. Later imports win, `filter` lists are concatenated (AND).
/// Import paths are relative to the top-level rule file.
pub fn load_yaml(file: &Path) -> Result<(Map<String, Value>, Vec<PathBuf>)> {
    let mut files = vec![file.to_path_buf()];
    let mut rule = Map::new();
    rule.insert("rule_file".into(), json!(file.to_string_lossy()));
    let base = file.parent().unwrap_or(Path::new("."));
    let mut stack: Vec<PathBuf> = Vec::new();
    let mut current = file.to_path_buf();
    let mut seen = 0;
    loop {
        if current != file && !files.contains(&current) {
            files.push(current.clone());
        }
        let Value::Object(mut loaded) = read_yaml(&current)? else { bail!("{} must be a YAML map", current.display()) };
        if let (Some(Value::Array(mine)), Some(Value::Array(theirs))) = (rule.get("filter"), loaded.get("filter")) {
            let merged: Vec<Value> = theirs.iter().chain(mine).cloned().collect();
            rule.insert("filter".into(), Value::Array(merged));
        }
        loaded.extend(rule);
        rule = loaded;
        if let Some(imports) = rule.remove("import") {
            let list = match imports {
                Value::String(s) => vec![s],
                Value::Array(a) => a.into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                _ => bail!("import must be a string or a list"),
            };
            stack.extend(list.into_iter().map(|p| base.join(p)));
        }
        seen += 1;
        if seen > 100 {
            bail!("import chain too deep (cycle?) in {}", file.display());
        }
        match stack.pop() {
            Some(next) => current = next,
            None => return Ok((rule, files)),
        }
    }
}

/// One `filter_terms_file` entry: the values of a text file, one per line, as a `terms` filter on `field`.
struct TermsFile {
    field: String,
    path: PathBuf,
    negate: bool,
}

/// Elasticsearch refuses a `terms` query with more values than `index.max_terms_count`.
const MAX_TERMS: usize = 65_536;

impl TermsFile {
    /// The `terms` filter (inside `bool.must_not` when `negate`). Blank lines and lines starting with `#` are skipped.
    fn filter(&self) -> Result<Value> {
        let text = std::fs::read_to_string(&self.path).with_context(|| format!("filter_terms_file {}", self.path.display()))?;
        let mut values: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        values.sort_unstable();
        values.dedup();
        if values.is_empty() {
            bail!("filter_terms_file {} has no value", self.path.display());
        }
        if values.len() > MAX_TERMS {
            bail!("filter_terms_file {} has {} values, Elasticsearch accepts {MAX_TERMS} in a terms query", self.path.display(), values.len());
        }
        let terms = json!({"terms": {self.field.clone(): values}});
        Ok(if self.negate { json!({"bool": {"must_not": [terms]}}) } else { terms })
    }
}

/// `filter_terms_file`: a map, or a list of maps, with `field`, `path` (relative to the rule file) and `negate`.
fn terms_files(raw: &Map<String, Value>) -> Result<Vec<TermsFile>> {
    let items = match raw.get("filter_terms_file") {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::Array(a)) => a.clone(),
        Some(v @ Value::Object(_)) => vec![v.clone()],
        Some(_) => bail!("filter_terms_file must be a map or a list of maps with field and path"),
    };
    let base = raw.get("rule_file").and_then(Value::as_str).map(Path::new).and_then(Path::parent).unwrap_or(Path::new("."));
    items
        .iter()
        .map(|item| {
            let m = item.as_object().context("filter_terms_file entries must be maps with field and path")?;
            if let Some(k) = m.keys().find(|k| !["field", "path", "negate"].contains(&k.as_str())) {
                bail!("filter_terms_file: option {k} is not supported (field, path, negate)");
            }
            let get = |k: &str| m.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).with_context(|| format!("filter_terms_file needs a {k}"));
            Ok(TermsFile { field: get("field")?.to_string(), path: base.join(get("path")?), negate: m.get("negate").and_then(Value::as_bool).unwrap_or(false) })
        })
        .collect()
}

/// Hash of a rule file and everything it imports; changes when any of them changes.
pub fn file_hash(file: &Path, conf: &Config) -> u64 {
    use std::hash::{Hash, Hasher};
    let (raw, mut files) = read_rule(file, conf).unwrap_or_else(|_| (Map::new(), vec![file.to_path_buf()]));
    files.extend(crate::sigma::files(&raw, &sigma_corpus(conf)));
    files.extend(terms_files(&raw).unwrap_or_default().into_iter().map(|t| t.path));
    let mut h = rustc_hash::FxHasher::default();
    for f in files {
        match std::fs::read(&f) {
            Ok(bytes) => bytes.hash(&mut h),
            Err(_) => f.hash(&mut h), // missing import still changes the hash
        }
    }
    h.finish()
}

fn dur_opt(raw: &Map<String, Value>, key: &str) -> Result<Option<Dur>> {
    raw.get(key)
        .map(|v| parse_duration_map(v).with_context(|| format!("invalid time format for {key}")))
        .transpose()
}

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

pub fn load(file: &Path, conf: &Config) -> Result<Rule> {
    let (mut raw, _) = read_rule(file, conf)?;
    // Every rule uses the daemon's Elasticsearch connection; a rule that names a different one would
    // silently query the wrong cluster, so refuse it.
    for k in [
        "es_host", "es_hosts", "es_port", "es_username", "es_password", "es_bearer", "es_api_key", "es_url_prefix", "use_ssl", "verify_certs", "ca_certs", "client_cert",
        "client_key",
    ] {
        if let Some(v) = raw.get(k)
            && conf.raw.get(k) != Some(v)
        {
            bail!("per-rule Elasticsearch connection ({k}) is not supported: set it in config.yaml");
        }
    }
    for (k, v) in &conf.raw {
        raw.entry(k.clone()).or_insert_with(|| v.clone());
    }
    crate::sigma::apply(&mut raw, &conf.attack, &sigma_corpus(conf))?;
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("rule");
    let name = raw.get("name").and_then(Value::as_str).unwrap_or(stem).to_string();
    raw.insert("name".into(), json!(name));
    for key in ["type", "index", "alert"] {
        if !raw.contains_key(key) {
            bail!("missing required option: {key}");
        }
    }
    let kind = match raw["type"].as_str() {
        Some("any") => Kind::Any,
        Some("frequency") => Kind::Frequency,
        Some("spike") => Kind::Spike,
        Some("flatline") => Kind::Flatline,
        Some("blacklist") => Kind::Blacklist,
        Some("whitelist") => Kind::Whitelist,
        Some("change") => Kind::Change,
        Some("new_term") => Kind::NewTerm,
        Some("cardinality") => Kind::Cardinality,
        Some("metric_aggregation") => Kind::MetricAggregation,
        Some("percentage_match") => Kind::PercentageMatch,
        Some("spike_aggregation") => Kind::SpikeAggregation,
        Some("correlation") => Kind::Correlation,
        other => bail!("rule type {other:?} is not supported yet"),
    };
    for unsupported in ["include_rule_params_in_matches"] {
        if raw.get(unsupported).is_some_and(|v| !matches!(v, Value::Bool(false) | Value::Null)) {
            bail!("option {unsupported} is not supported yet");
        }
    }
    let flag = |raw: &Map<String, Value>, k: &str| raw.get(k).and_then(Value::as_bool).unwrap_or(false);
    let limit_execution = match raw.get("limit_execution") {
        None | Some(Value::Null | Value::Bool(false)) => None,
        Some(Value::String(c)) if c.trim().is_empty() => None,
        Some(Value::String(c)) => {
            c.parse::<croner::Cron>().map_err(|e| anyhow::anyhow!("invalid limit_execution cron expression {c:?}: {e}"))?;
            Some(c.clone())
        }
        Some(_) => bail!("limit_execution must be a cron expression string"),
    };
    let active_hours = match raw.get("active_hours") {
        None | Some(Value::Null) => None,
        Some(v) => Some(crate::hours::ActiveHours::parse(v)?),
    };
    let mitre_attack = crate::mitre::parse(raw.get("mitre_attack"), &conf.attack, &name)?;
    let (kibana_discover, opensearch_discover) = (flag(&raw, "generate_kibana_discover_url"), flag(&raw, "generate_opensearch_discover_url"));
    if kibana_discover {
        crate::discover::validate_kibana(&raw)?;
    }
    if opensearch_discover {
        crate::discover::validate(&raw, "opensearch")?;
    }
    let enhancements = enhancements::load(raw.get("match_enhancements"), &raw)?;
    match raw.get("jinja_filters") {
        None | Some(Value::Null | Value::Bool(false)) => {}
        Some(Value::Array(a)) if a.is_empty() => {}
        Some(_) => bail!("jinja_filters name Python classes, which cannot be loaded: custom Jinja filters are not supported"),
    }
    let aggregation = match raw.get("aggregation") {
        None | Some(Value::Null) => None,
        Some(v) => Some(match v.get("schedule").and_then(Value::as_str) {
            Some(cron) => {
                cron.parse::<croner::Cron>().map_err(|e| anyhow::anyhow!("invalid aggregation schedule {cron:?}: {e}"))?;
                Aggregation::Cron(cron.to_string())
            }
            None => Aggregation::Timespan(parse_duration_map(v).context("invalid time format for aggregation")?),
        }),
    };
    if raw.get("summary_table_type").and_then(Value::as_str) == Some("html") {
        bail!("summary_table_type html is not supported yet (ascii and markdown are)");
    }
    if raw.get("_source_enabled").and_then(Value::as_bool) == Some(false) {
        bail!("option _source_enabled: false is not supported yet");
    }
    let use_count_query = raw.get("use_count_query").and_then(Value::as_bool).unwrap_or(false);
    let use_terms_query = raw.get("use_terms_query").and_then(Value::as_bool).unwrap_or(false);
    if use_count_query && !matches!(kind, Kind::Frequency | Kind::Spike | Kind::Flatline) {
        bail!("use_count_query is only supported for frequency, spike and flatline rules");
    }
    if use_terms_query && !matches!(kind, Kind::Frequency | Kind::Spike | Kind::Flatline | Kind::NewTerm) {
        bail!("use_terms_query is only supported for frequency, spike, flatline and new_term rules");
    }
    let timestamp_type = match raw.get("timestamp_type").and_then(Value::as_str).unwrap_or("iso").trim().to_lowercase().as_str() {
        "iso" => TsType::Iso,
        "unix" => TsType::Unix,
        "unix_ms" => TsType::UnixMs,
        t => bail!("timestamp_type {t} is not supported (iso, unix, unix_ms)"),
    };
    let timestamp_field = raw.get("timestamp_field").and_then(Value::as_str).unwrap_or("@timestamp").to_string();

    let mut compound_query_key = Vec::new();
    let query_key = match raw.get("query_key").cloned() {
        Some(Value::Array(list)) => {
            let keys: Vec<String> = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            match keys.len() {
                0 => None,
                1 => Some(keys[0].clone()),
                _ => {
                    compound_query_key = keys.clone();
                    Some(keys.join(","))
                }
            }
        }
        Some(Value::String(s)) => Some(s),
        _ => None,
    };
    match &query_key {
        Some(q) => raw.insert("query_key".into(), json!(q)),
        None => raw.remove("query_key"),
    };

    let compare_key = raw.get("compare_key").map(str_list).unwrap_or_default();
    if compare_key.len() > 1 {
        raw.insert("compare_key".into(), json!(compare_key.join(",")));
    }

    let timeframe = dur_opt(&raw, "timeframe")?;
    let num_events = raw.get("num_events").and_then(Value::as_u64).unwrap_or(0);
    let need = |keys: &[&str]| -> Result<()> {
        match keys.iter().find(|k| !raw.contains_key(**k) && **k != "timeframe") {
            Some(k) => bail!("missing required option for a {:?} rule: {k}", raw["type"]),
            None if keys.contains(&"timeframe") && timeframe.is_none() => bail!("missing required option for a {:?} rule: timeframe", raw["type"]),
            None => Ok(()),
        }
    };
    match kind {
        Kind::Any => {}
        Kind::Frequency => {
            need(&["num_events", "timeframe"])?;
            if num_events == 0 {
                bail!("num_events must be positive");
            }
        }
        Kind::Spike => need(&["timeframe", "spike_height", "spike_type"])?,
        Kind::Flatline => need(&["timeframe", "threshold"])?,
        Kind::Blacklist => need(&["compare_key", "blacklist"])?,
        Kind::Whitelist => need(&["compare_key", "whitelist", "ignore_null"])?,
        Kind::Change => need(&["query_key", "compare_key", "ignore_null"])?,
        Kind::NewTerm => {
            if !raw.contains_key("fields") && query_key.is_none() {
                bail!("fields or query_key must be specified");
            }
        }
        Kind::Cardinality => {
            need(&["timeframe", "cardinality_field"])?;
            if !raw.contains_key("max_cardinality") && !raw.contains_key("min_cardinality") {
                bail!("CardinalityRule must have one of either max_cardinality or min_cardinality");
            }
        }
        Kind::MetricAggregation => {
            need(&["metric_agg_key", "metric_agg_type"])?;
            if !raw.contains_key("max_threshold") && !raw.contains_key("min_threshold") {
                bail!("MetricAggregationRule must have at least one of either max_threshold or min_threshold");
            }
        }
        Kind::SpikeAggregation => need(&["timeframe", "spike_height", "spike_type", "metric_agg_key", "metric_agg_type"])?,
        Kind::Correlation => need(&["correlation_leaves", "correlation_query", "query_key", "timeframe"])?,
        Kind::PercentageMatch => {
            need(&["match_bucket_filter"])?;
            if !raw.contains_key("max_percentage") && !raw.contains_key("min_percentage") {
                bail!("PercentageMatchRule must have at least one of either min_percentage or max_percentage");
            }
            if compound_query_key.len() > 1 {
                bail!("a compound query_key is not supported for percentage_match rules");
            }
        }
    }
    let buffer_time = dur_opt(&raw, "buffer_time")?.unwrap_or(conf.buffer_time);
    let run_every = dur_opt(&raw, "run_every")?.unwrap_or(conf.run_every);
    let use_run_every_query_size = raw.get("use_run_every_query_size").and_then(Value::as_bool).unwrap_or(false);
    let (agg_query, bucket_interval) = if kind.is_agg_query() {
        if raw.contains_key("ingest_timestamp_field") {
            bail!("ingest_timestamp_field is not supported for {:?} rules", raw["type"]);
        }
        agg_options(kind, &raw, buffer_time, run_every, use_run_every_query_size)?
    } else {
        (None, None)
    };
    if raw.get("scan_entire_timeframe").and_then(Value::as_bool).unwrap_or(false) && timeframe.is_none() {
        bail!("scan_entire_timeframe can only be used if there is a timeframe specified");
    }

    let mut compound_aggregation_key = Vec::new();
    let aggregation_key = match raw.get("aggregation_key").cloned() {
        Some(Value::Array(list)) => {
            let keys: Vec<String> = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            let joined = keys.join(",");
            compound_aggregation_key = keys;
            raw.insert("aggregation_key".into(), json!(joined));
            Some(joined)
        }
        Some(Value::String(k)) => Some(k),
        _ => None,
    };
    if use_terms_query && query_key.is_none() {
        bail!("query_key must be specified with use_terms_query");
    }
    let suffix = raw.get("string_multi_field_name").and_then(Value::as_str).unwrap_or(".keyword").to_string();
    let raw_count_keys = raw.get("raw_count_keys").and_then(Value::as_bool).unwrap_or(true);
    let top_count_keys: Vec<String> = raw
        .get("top_count_keys")
        .map(str_list)
        .unwrap_or_default()
        .into_iter()
        .map(|k| if raw_count_keys && !k.ends_with(&suffix) { format!("{k}{suffix}") } else { k })
        .collect();
    let top_count_number = raw.get("top_count_number").and_then(Value::as_u64).unwrap_or(5);
    let split_on_limit = raw.get("split_on_limit").and_then(Value::as_bool).unwrap_or(false);
    let search_timeout = dur_opt(&raw, "search_timeout")?;
    if search_timeout.is_some_and(|t| t < 1_000) {
        bail!("search_timeout must be at least one millisecond");
    }
    let terminate_after = match raw.get("terminate_after") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().filter(|n| *n > 0).context("terminate_after must be a positive integer")?),
    };
    let mut search_params = String::new();
    for key in ["preference", "routing"] {
        match raw.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if !s.is_empty() => search_params.push_str(&format!("&{key}={}", crate::discover::quote_plus(s))),
            Some(_) => bail!("{key} must be a non-empty string"),
        }
    }
    let ingest_field = raw.get("ingest_timestamp_field").and_then(Value::as_str).map(String::from);
    let exponential_realert = dur_opt(&raw, "exponential_realert")?;
    let query_timezone = match raw.get("query_timezone").and_then(Value::as_str).filter(|t| !t.is_empty()) {
        Some(t) => Some(t.parse::<chrono_tz::Tz>().map_err(|_| anyhow::anyhow!("unknown query_timezone {t:?}"))?),
        None => None,
    };
    let include_fields = match raw.get("include_fields") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) => Some(a.iter().filter_map(|v| v.as_str().map(String::from)).collect()),
        Some(_) => bail!("include_fields option must be a list"),
    };
    let jinja_template = jinja_template_of(&raw)?;

    // What to ask ES for. Types that treat every hit as a match need whole documents; the others
    // fetch only the fields they use and get the full document for matches later (`_mget`).
    let user_include = raw.get("include").map(str_list);
    let full = user_include.is_some()
        || matches!(kind, Kind::Any | Kind::Blacklist | Kind::Whitelist)
        || raw.get("fetch_full_source").and_then(Value::as_bool).unwrap_or(false);
    let mut include: Vec<String> = match (&user_include, full) {
        (Some(u), _) => u.clone(),
        (None, true) => vec!["*".into()],
        (None, false) => vec![],
    };
    include.extend(query_key.clone());
    include.extend(compound_query_key.iter().cloned());
    include.extend(compare_key.iter().cloned());
    include.extend(compound_aggregation_key.iter().cloned());
    include.extend(aggregation_key.clone());
    include.push(timestamp_field.clone());
    if kind == Kind::Correlation {
        let leaves = raw.get("correlation_leaves").and_then(Value::as_object).into_iter().flat_map(Map::values);
        include.extend(leaves.filter_map(|l| l.get("query_key").and_then(Value::as_str)).map(String::from));
    }
    if !full {
        include.extend(raw.get("cardinality_field").and_then(Value::as_str).map(String::from));
        include.extend(raw.get("field_value").and_then(Value::as_str).map(String::from));
        if kind == Kind::NewTerm {
            for f in raw.get("fields").into_iter().filter_map(Value::as_array).flatten() {
                match f {
                    Value::Array(sub) => include.extend(sub.iter().filter_map(|x| x.as_str().map(String::from))),
                    Value::String(s) => include.push(s.clone()),
                    _ => {}
                }
            }
        }
    }
    include.sort();
    include.dedup();
    let enrich = !full && !kind.is_agg_query();
    let read_doc_values = raw.get("read_doc_values").and_then(Value::as_bool).unwrap_or(false);
    if read_doc_values && !(enrich && matches!(kind, Kind::Frequency | Kind::Flatline | Kind::Spike | Kind::Correlation) && timestamp_type == TsType::Iso) {
        bail!("read_doc_values applies to frequency, flatline, spike and correlation rules with an ISO timestamp, without include or fetch_full_source");
    }

    let mut entries: Vec<(String, Option<Map<String, Value>>)> = match &raw["alert"] {
        Value::String(s) => vec![(s.clone(), None)],
        Value::Array(a) => a.iter().map(alert_entry).collect::<Result<_>>()?,
        _ => bail!("alert must be a string or a list"),
    };
    // Upstream's `alerts_order`: jira runs first, so email and slack can link its ticket. The sort is stable.
    entries.sort_by_key(|(name, _)| if name == "jira" { 0 } else { 1 });
    let (alerts, alert_configs): (Vec<_>, Vec<_>) = entries.into_iter().unzip();

    resolve_refs(&mut raw);
    let mut filter = match raw.get("filter") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => bail!("filter must be a list"),
    };
    for t in terms_files(&raw)? {
        filter.push(t.filter()?);
    }
    let max_query_size = raw.get("max_query_size").and_then(Value::as_u64).unwrap_or(conf.max_query_size);
    let query_lang = querylang::detect(&filter)?;
    if let Some(lang) = query_lang {
        let what = lang.key();
        if use_count_query || use_terms_query || kind.is_agg_query() || kind == Kind::NewTerm || kind == Kind::Correlation || !top_count_keys.is_empty() {
            bail!("{what} filters only work with plain hit queries: not with use_count_query, use_terms_query, top_count_keys, new_term, correlation or the aggregation rule types");
        }
        querylang::apply_limit(&mut filter, max_query_size);
    } else if split_on_limit {
        bail!("split_on_limit only applies to rules with an eql or esql filter; other searches are paged");
    }

    let correlation = if kind == Kind::Correlation { Some(correlation_options(&raw, query_key.as_deref(), compound_query_key.len() > 1)?) } else { None };

    Ok(Rule {
        correlation,
        realert: dur_opt(&raw, "realert")?.unwrap_or(if aggregation.is_some() { 0 } else { MINUTE }),
        realert_key: raw.get("realert_key").and_then(Value::as_str).unwrap_or(&name).to_string(),
        buffer_time,
        run_every,
        agg_query,
        bucket_interval,
        use_run_every_query_size,
        sync_bucket_interval: raw.get("sync_bucket_interval").and_then(Value::as_bool).unwrap_or(false),
        allow_buffer_time_overlap: raw.get("allow_buffer_time_overlap").and_then(Value::as_bool).unwrap_or(false),
        query_delay: dur_opt(&raw, "query_delay")?.unwrap_or(0),
        use_local_time: raw.get("use_local_time").and_then(Value::as_bool).unwrap_or(true),
        file: file.to_path_buf(),
        compare_key,
        aggregation,
        aggregation_key,
        compound_aggregation_key,
        use_count_query,
        use_terms_query,
        terms_size: raw.get("terms_size").and_then(Value::as_u64).unwrap_or(50),
        top_count_keys,
        top_count_number,
        ingest_field,
        search_timeout,
        terminate_after,
        search_params,
        split_on_limit,
        read_doc_values,
        exponential_realert,
        query_timezone,
        allow_degraded: raw.get("allow_queries_on_degraded_indices").and_then(Value::as_bool).unwrap_or(false),
        include_fields,
        jinja_template,
        use_strftime_index: raw.get("use_strftime_index").and_then(Value::as_bool).unwrap_or(false),
        search_extra_index: raw.get("search_extra_index").and_then(Value::as_bool).unwrap_or(false),
        enrich: enrich && query_lang.is_none(),
        attach_related: raw.get("attach_related").and_then(Value::as_bool).unwrap_or(false),
        scan_entire_timeframe: raw.get("scan_entire_timeframe").and_then(Value::as_bool).unwrap_or(false),
        max_query_size,
        limit_execution,
        limit_execution_coverage: flag(&raw, "limit_execution_coverage"),
        active_hours,
        mitre_attack,
        kibana_discover,
        opensearch_discover,
        enhancements,
        run_enhancements_first: flag(&raw, "run_enhancements_first"),
        query_lang,
        max_scrolling_count: raw.get("max_scrolling_count").and_then(Value::as_u64).unwrap_or(conf.max_scrolling_count),
        index: raw["index"].as_str().context("index must be a string")?.to_string(),
        name,
        kind,
        filter,
        include,
        timestamp_field,
        timestamp_type,
        query_key,
        compound_query_key,
        timeframe,
        num_events,
        alerts,
        alert_configs,
        raw,
    })
}

/// `correlation_leaves` and `correlation_query`. Every leaf is its own search, so a leaf can only use Query DSL filters.
fn correlation_options(raw: &Map<String, Value>, query_key: Option<&str>, compound: bool) -> Result<CorrelationSpec> {
    let map = raw["correlation_leaves"].as_object().context("correlation_leaves must be a map of leaf name to leaf")?;
    let mut leaves: Vec<Leaf> = Vec::new();
    for (name, item) in map {
        if name.is_empty() || !name.chars().all(crate::correlation::is_name_char) {
            bail!("correlation leaf {name:?}: a name may only contain letters, digits, '_' and '-'");
        }
        if crate::correlation::KEYWORDS.contains(&name.to_ascii_uppercase().as_str()) {
            bail!("correlation leaf {name:?}: AND, OR, THEN and NOT are keywords of correlation_query");
        }
        let m = item.as_object().with_context(|| format!("correlation leaf {name} must be a map"))?;
        if let Some(k) = m.keys().find(|k| !["filter", "index", "query_key", "num_events"].contains(&k.as_str())) {
            bail!("correlation leaf {name}: option {k} is not supported (filter, index, query_key, num_events)");
        }
        let filter = match m.get("filter") {
            Some(Value::Array(a)) if !a.is_empty() => a.clone(),
            _ => bail!("correlation leaf {name} needs a non-empty filter list"),
        };
        if querylang::detect(&filter)?.is_some() {
            bail!("correlation leaf {name}: eql and esql filters are not supported in correlation rules");
        }
        let index = match m.get("index") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(_) => bail!("correlation leaf {name}: index must be a string"),
        };
        let leaf_key = match m.get("query_key") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(_) => bail!("correlation leaf {name}: query_key must be a single field name"),
        };
        if leaf_key.is_some() && (query_key.is_none() || compound) {
            bail!("correlation leaf {name}: a leaf query_key needs a single-field query_key on the rule");
        }
        let num_events = match m.get("num_events") {
            None | Some(Value::Null) => 1,
            Some(v) => v.as_u64().filter(|n| *n > 0).with_context(|| format!("correlation leaf {name}: num_events must be a positive integer"))?,
        };
        leaves.push(Leaf { name: name.clone(), filter, index, query_key: leaf_key, num_events });
    }
    let src = raw["correlation_query"].as_str().context("correlation_query must be a string")?;
    let names: Vec<String> = leaves.iter().map(|l| l.name.clone()).collect();
    let query = crate::correlation::parse(src, &names).with_context(|| format!("correlation_query {src:?}"))?;
    Ok(CorrelationSpec { leaves, query })
}

const METRIC_TYPES: [&str; 7] = ["min", "max", "avg", "sum", "cardinality", "value_count", "percentiles"];

/// The aggregation sub-tree and `bucket_interval` of the aggregation rule types (`BaseAggregationRule`).
fn agg_options(kind: Kind, raw: &Map<String, Value>, buffer_time: Dur, run_every: Dur, run_every_size: bool) -> Result<(Option<Value>, Option<(String, Dur)>)> {
    let interval = match raw.get("bucket_interval").filter(|v| v.as_object().is_some_and(|m| !m.is_empty())) {
        None => None,
        Some(v) => {
            let m = v.as_object().expect("filtered above");
            let (unit, n) = [("seconds", 's'), ("minutes", 'm'), ("hours", 'h'), ("days", 'd'), ("weeks", 'w')]
                .iter()
                .find_map(|(name, u)| m.get(*name).map(|n| (*u, crate::field::py_str(n))))
                .context("Unsupported window size")?;
            let dur = parse_duration_map(v).context("invalid time format for bucket_interval")?;
            if dur < SECOND {
                bail!("bucket_interval must be at least one second");
            }
            let (what, size) = if run_every_size { ("run_every", run_every) } else { ("Buffer_time", buffer_time) };
            if size % dur != 0 {
                bail!("{what} must be evenly divisible by bucket_interval if specified");
            }
            Some((format!("{n}{unit}"), dur))
        }
    };
    if kind == Kind::PercentageMatch {
        let filter = raw["match_bucket_filter"].clone();
        let element = json!({"percentage_match_aggs": {"filters": {"other_bucket": true, "filters": {"match_bucket": {"bool": {"must": filter}}}}}});
        return Ok((Some(element), interval));
    }
    if kind == Kind::SpikeAggregation && interval.is_some() {
        bail!("bucket intervals are not supported for spike aggregation alerts");
    }
    let ty = raw["metric_agg_type"].as_str().unwrap_or_default();
    if !METRIC_TYPES.contains(&ty) {
        bail!("metric_agg_type must be one of {METRIC_TYPES:?}");
    }
    let key = crate::field::py_str(&raw["metric_agg_key"]);
    let mut inner = match raw.get("metric_agg_script").filter(|v| !matches!(v, Value::Null | Value::Bool(false)) && *v != &json!("")) {
        Some(Value::Object(m)) => m.clone(),
        Some(script) => Map::from_iter([("script".to_string(), script.clone())]),
        None => Map::from_iter([("field".to_string(), json!(key))]),
    };
    if ty == "percentiles" && !inner.contains_key("percents") {
        match raw.get("percentile_range") {
            None | Some(Value::Null) => bail!("percentile_range must be specified for percentiles aggregation"),
            Some(p) => inner.insert("percents".into(), json!([p])),
        };
    }
    Ok((Some(json!({format!("metric_{key}_{ty}"): {ty: inner}})), interval))
}

/// `$other_key$` values are replaced by that rule key's value (alerter options reference rule fields).
fn resolve_refs(raw: &mut Map<String, Value>) {
    fn walk(v: &mut Value, rule: &Map<String, Value>) {
        match v {
            Value::Object(m) => m.values_mut().for_each(|x| walk(x, rule)),
            Value::Array(a) => a.iter_mut().for_each(|x| walk(x, rule)),
            Value::String(s) if s.len() > 2 && s.starts_with('$') && s.ends_with('$') => {
                if let Some(r) = rule.get(&s[1..s.len() - 1]) {
                    *v = r.clone();
                }
            }
            _ => {}
        }
    }
    let snapshot = raw.clone();
    raw.values_mut().for_each(|v| walk(v, &snapshot));
}

/// Loads every rule. Invalid files abort unless `skip_invalid`; duplicate names always abort.
pub fn load_all(conf: &Config, only: Option<&str>) -> Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = Vec::new();
    for file in discover(conf, only)? {
        match load(&file, conf) {
            Ok(r) if r.raw.get("is_enabled").and_then(Value::as_bool) == Some(false) => {}
            Ok(r) => {
                if rules.iter().any(|x| x.name == r.name) {
                    bail!("duplicate rule named {}", r.name);
                }
                rules.push(r);
            }
            Err(e) if conf.skip_invalid => log::error!("Invalid rule file skipped: {}: {e:#}", file.display()),
            Err(e) => bail!("error loading file {}: {e:#}", file.display()),
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_chain_merges_filters_and_keys() {
        let dir = std::env::temp_dir().join(format!("ea-rule-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("base.yaml"), "index: logs-*\nfilter:\n- term: {a: 1}\nrealert: {minutes: 5}\n").unwrap();
        std::fs::write(dir.join("r.yaml"), "import: base.yaml\nname: r\ntype: any\nalert: debug\nfilter:\n- term: {b: 2}\n").unwrap();
        let (raw, files) = load_yaml(&dir.join("r.yaml")).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(raw["index"], json!("logs-*"));
        assert_eq!(raw["filter"], json!([{"term": {"a": 1}}, {"term": {"b": 2}}]));
        assert!(!raw.contains_key("import"));
        std::fs::remove_dir_all(dir).ok();
    }

    const SIGMA: &str = "title: Encoded PowerShell\nlevel: high\nlogsource: {product: windows}\ndetection:\n  sel: {Image|endswith: '\\\\ps.exe'}\n  condition: sel\n";

    fn sigma_setup(name: &str, config: &str) -> (PathBuf, Config) {
        let dir = std::env::temp_dir().join(format!("ea-sigma-folders-{}-{name}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("sigma/win")).unwrap();
        std::fs::write(dir.join("sigma/win/ps.yml"), SIGMA).unwrap();
        std::fs::write(dir.join("sigma/win/notes.txt"), "not a rule").unwrap();
        let config = config.replace("DIR", &dir.to_string_lossy());
        std::fs::write(dir.join("config.yaml"), format!("rules_folder: {0}/missing\nes_host: h\nes_port: 9200\nwriteback_index: wb\nrun_every: {{minutes: 1}}\nbuffer_time: {{minutes: 5}}\n{config}", dir.display())).unwrap();
        let conf = Config::load(&dir.join("config.yaml")).unwrap();
        (dir, conf)
    }

    #[test]
    fn sigma_folders_load_plain_sigma_files() {
        let (dir, conf) = sigma_setup("ok", "sigma_folders: [DIR/sigma]\nsigma_defaults:\n  alert: [debug]\n  index: logs-*\n  realert: {minutes: 10}\n");
        let files = discover(&conf, None).unwrap();
        assert_eq!(files, vec![dir.join("sigma/win/ps.yml")]);
        let r = load(&files[0], &conf).unwrap();
        assert_eq!((r.name.as_str(), r.raw["alert_subject"].as_str(), r.raw["priority"].as_u64()), ("ps", Some("Encoded PowerShell"), Some(2)));
        assert_eq!(r.realert, 10 * MINUTE);
        assert_eq!(r.filter.len(), 1);
        // --rule finds a Sigma file by name, and the hash follows the file.
        assert_eq!(discover(&conf, Some("ps.yml")).unwrap(), files);
        let before = file_hash(&files[0], &conf);
        std::fs::write(&files[0], SIGMA.replace("high", "low")).unwrap();
        assert_ne!(before, file_hash(&files[0], &conf));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sigma_folders_need_an_alert_and_a_real_folder() {
        let (dir, conf) = sigma_setup("noalert", "sigma_folders: DIR/sigma\nsigma_defaults: {index: logs-*}\n");
        let err = format!("{:#}", load(&dir.join("sigma/win/ps.yml"), &conf).err().unwrap());
        assert!(err.contains("need an alert"), "{err}");
        let (_, conf) = sigma_setup("nofolder", "sigma_folders: [DIR/nope]\n");
        assert!(discover(&conf, None).unwrap_err().to_string().contains("sigma folder does not exist"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sigma_folders_skip_filters_and_the_rules_a_correlation_uses() {
        let (dir, conf) = sigma_setup("corr", "sigma_folders: [DIR/sigma]\nsigma_defaults: {alert: [debug], index: logs-*}\n");
        let sigma = dir.join("sigma");
        std::fs::remove_dir_all(sigma.join("win")).unwrap();
        let det = |name: &str, field: &str| format!("title: {name}\nname: {name}\nlogsource: {{product: windows}}\ndetection: {{s: {{{field}: 1}}, condition: s}}\n");
        let corr = |ty: &str, extra: &str| format!("title: c\ncorrelation: {{type: {ty}, rules: [failed], group-by: [U], timespan: 1m, condition: {{gte: 3{extra}}}}}\n");
        std::fs::write(sigma.join("failed.yml"), det("failed", "A")).unwrap();
        std::fs::write(sigma.join("other.yml"), det("other", "B")).unwrap();
        std::fs::write(sigma.join("a_corr.yml"), corr("event_count", "")).unwrap();
        std::fs::write(sigma.join("mf_other.yml"), "title: f\nfilter:\n  rules: [other]\n  selection: {User: SYSTEM}\n  condition: selection\n").unwrap();
        let names = |conf: &Config| discover(conf, None).unwrap().iter().map(|f| f.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        // The filter is no rule, and `failed` only feeds the correlation.
        assert_eq!(names(&conf), vec!["a_corr.yml", "other.yml"]);
        let c = load(&sigma.join("a_corr.yml"), &conf).unwrap();
        assert_eq!((c.name.as_str(), c.raw["type"].as_str(), c.raw["num_events"].as_u64()), ("a_corr", Some("frequency"), Some(3)));
        let o = load(&sigma.join("other.yml"), &conf).unwrap();
        assert!(o.filter[0].to_string().contains("must_not"));
        // A correlation that does not load leaves its rules running; generate: true keeps them running too.
        std::fs::write(sigma.join("a_corr.yml"), corr("value_sum", ", field: V")).unwrap();
        assert_eq!(names(&conf), vec!["a_corr.yml", "failed.yml", "other.yml"]);
        std::fs::write(sigma.join("a_corr.yml"), format!("generate: true\n{}", corr("event_count", ""))).unwrap();
        assert_eq!(names(&conf), vec!["a_corr.yml", "failed.yml", "other.yml"]);
        // Editing a filter changes the hash of the rule it applies to, and only that one.
        let (before_o, before_f) = (file_hash(&sigma.join("other.yml"), &conf), file_hash(&sigma.join("failed.yml"), &conf));
        std::fs::write(sigma.join("mf_other.yml"), "title: f\nfilter:\n  rules: [other]\n  selection: {User: ROOT}\n  condition: selection\n").unwrap();
        *conf.sigma_cache.lock().unwrap() = None;
        assert_ne!(before_o, file_hash(&sigma.join("other.yml"), &conf));
        assert_eq!(before_f, file_hash(&sigma.join("failed.yml"), &conf));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sigma_defaults_cannot_name_the_rule() {
        let dir = std::env::temp_dir().join(format!("ea-sigma-folders-{}-name", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), "rules_folder: r\nes_host: h\nes_port: 9200\nwriteback_index: wb\nrun_every: {minutes: 1}\nbuffer_time: {minutes: 5}\nsigma_defaults: {name: x}\n").unwrap();
        assert!(format!("{:#}", Config::load(&dir.join("config.yaml")).err().unwrap()).contains("cannot set name"));
        std::fs::remove_dir_all(dir).ok();
    }

    fn load_text(name: &str, extra: &str) -> Result<Rule> {
        let dir = std::env::temp_dir().join(format!("ea-rule-opts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{name}.yaml"));
        std::fs::write(&file, format!("name: {name}\ntype: any\nindex: logs-*\nalert: debug\n{extra}")).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        load(&file, &conf)
    }

    fn load_correlation(name: &str, body: &str) -> Result<Rule> {
        let dir = std::env::temp_dir().join(format!("ea-rule-corr-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, format!("name: {name}\ntype: correlation\nindex: logs-*\nalert: debug\n{body}")).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        load(&file, &conf)
    }

    const CORR_OK: &str = "query_key: host.name\ntimeframe: {hours: 1}\ncorrelation_query: a then (b OR c)\ncorrelation_leaves:\n  a: {filter: [{term: {k: a}}], num_events: 3}\n  b: {filter: [{term: {k: b}}], index: other-*, query_key: host.id}\n  c: {filter: [{term: {k: c}}]}\n";

    #[test]
    fn correlation_rule_loads() {
        let r = load_correlation("ok", CORR_OK).unwrap();
        let c = r.correlation.unwrap();
        assert_eq!(c.leaves.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(c.leaves[1].index.as_deref(), Some("other-*"));
        assert_eq!(c.leaves[1].query_key.as_deref(), Some("host.id"));
        assert_eq!((c.leaves[0].num_events, c.leaves[1].num_events), (3, 1));
        assert_eq!(c.query.text, "a THEN (b OR c)");
        assert_eq!(r.include, ["@timestamp", "host.id", "host.name"], "only the pivot and the timestamp are fetched");
        assert!(r.enrich, "the matches get their whole documents with _mget");
    }

    #[test]
    fn correlation_rule_rejects_bad_options() {
        let leaves = "correlation_leaves:\n  a: {filter: [{term: {k: a}}]}\n  b: {filter: [{term: {k: b}}]}\n";
        let head = "query_key: host.name\ntimeframe: {hours: 1}\ncorrelation_query: a AND b\n";
        let bad = |name: &str, body: String, msg: &str| {
            let err = format!("{:#}", load_correlation(name, &body).map(|_| ()).expect_err(name));
            assert!(err.contains(msg), "{name}: {err}");
        };
        bad("noleaves", head.to_string(), "correlation_leaves");
        bad("noquery", format!("query_key: h\ntimeframe: {{hours: 1}}\n{leaves}"), "correlation_query");
        bad("notimeframe", format!("query_key: h\ncorrelation_query: a AND b\n{leaves}"), "timeframe");
        bad("nokey", format!("timeframe: {{hours: 1}}\ncorrelation_query: a AND b\n{leaves}"), "query_key");
        bad("steps", format!("query_key: h\ntimeframe: {{hours: 1}}\ncorrelation_steps:\n- {{name: a, filter: [{{term: {{k: a}}}}]}}\n"), "correlation_leaves");
        bad("list", format!("{head}correlation_leaves:\n- {{name: a, filter: [{{term: {{k: a}}}}]}}\n"), "must be a map");
        bad("dotname", format!("{head}correlation_leaves:\n  a.b: {{filter: [{{term: {{k: a}}}}]}}\n"), "may only contain");
        bad("keyword", format!("{head}correlation_leaves:\n  Then: {{filter: [{{term: {{k: a}}}}]}}\n"), "keywords");
        bad("nofilter", format!("{head}correlation_leaves:\n  a: {{}}\n  b: {{filter: [{{term: {{k: b}}}}]}}\n"), "non-empty filter");
        bad("eql", format!("{head}correlation_leaves:\n  a: {{filter: [{{eql: 'any where true'}}]}}\n  b: {{filter: [{{term: {{k: b}}}}]}}\n"), "eql and esql");
        bad("absent", format!("{head}correlation_leaves:\n  a: {{filter: [{{term: {{k: a}}}}]}}\n  b: {{absent: true, filter: [{{term: {{k: b}}}}]}}\n"), "option absent is not supported");
        bad("zero", format!("{head}correlation_leaves:\n  a: {{num_events: 0, filter: [{{term: {{k: a}}}}]}}\n  b: {{filter: [{{term: {{k: b}}}}]}}\n"), "positive integer");
        bad("compoundleafkey", format!("query_key: [a, b]\ntimeframe: {{hours: 1}}\ncorrelation_query: a AND b\ncorrelation_leaves:\n  a: {{query_key: x, filter: [{{term: {{k: a}}}}]}}\n  b: {{filter: [{{term: {{k: b}}}}]}}\n"), "single-field query_key");
        bad("unused", format!("query_key: h\ntimeframe: {{hours: 1}}\ncorrelation_query: a THEN a\n{leaves}"), "leaf b is not used");
        bad("unknown", format!("query_key: h\ntimeframe: {{hours: 1}}\ncorrelation_query: a AND b AND c\n{leaves}"), "unknown leaf c");
        bad("mixed", format!("query_key: h\ntimeframe: {{hours: 1}}\ncorrelation_query: a AND b THEN a\n{leaves}"), "without parentheses");
        bad("countquery", format!("{head}use_count_query: true\ndoc_type: x\n{leaves}"), "");
        bad("rulefilter", format!("{head}filter:\n- eql: 'any where true'\n{leaves}"), "eql");
        assert!(load_correlation("notok", &format!("query_key: h\ntimeframe: {{hours: 1}}\ncorrelation_query: a then not b\n{leaves}")).is_ok());
    }

    fn load_alert_list(name: &str, alert_yaml: &str, extra: &str) -> Result<Rule> {
        let dir = std::env::temp_dir().join(format!("ea-rule-alerts-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, format!("name: {name}\ntype: any\nindex: logs-*\nalert: {alert_yaml}\n{extra}")).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let r = load(&file, &conf);
        std::fs::remove_dir_all(dir).ok();
        r
    }

    #[test]
    fn alerts_with_their_own_options() {
        let r = load_alert_list("own", "[{post: {http_post_url: 'http://a'}}, debug, {post: {http_post_url: 'http://b', alert_subject: Other}}]", "http_post_url: http://rule\nalert_subject: Rule subject\n").unwrap();
        assert_eq!(r.alerts, ["post", "debug", "post"]);
        assert_eq!(r.alert_labels(), ["post", "debug", "post#2"]);
        assert!(r.alert_configs[1].is_none());
        // each alerter sees the rule with its entry's options laid over it
        let urls: Vec<_> = [0, 2].iter().map(|&i| {
            let eff = r.with_alert_config(r.alert_configs[i].as_ref().unwrap()).unwrap();
            let info = crate::alerters::Alerter::from_rule("post", &eff).unwrap().info();
            (info["http_post_webhook_url"].clone(), eff.raw["alert_subject"].clone())
        }).collect();
        assert_eq!(urls, [(json!(["http://a"]), json!("Rule subject")), (json!(["http://b"]), json!("Other"))]);
        // and the rule's own options are untouched
        assert_eq!(r.raw["http_post_url"], json!("http://rule"));
    }

    #[test]
    fn alert_entry_options_resolve_references_and_jinja() {
        let r = load_alert_list("refs", "[{debug: {alert_text_type: alert_text_jinja, alert_text: 'hello {{ who }}', name: renamed, copy: $from_rule$}}]", "from_rule: copied\n").unwrap();
        let eff = r.with_alert_config(r.alert_configs[0].as_ref().unwrap()).unwrap();
        assert_eq!((eff.raw["copy"].clone(), eff.name.as_str(), eff.jinja_template.as_deref()), (json!("copied"), "renamed", Some("hello {{ who }}")));
        assert_eq!(r.name, "refs");
        assert!(r.jinja_template.is_none());
        let bad = load_alert_list("badjinja", "[debug]", "").unwrap().with_alert_config(json!({"alert_text_type": "alert_text_jinja", "alert_text": "{{ oops"}).as_object().unwrap());
        assert!(bad.err().unwrap().to_string().contains("invalid jinja template"));
    }

    #[test]
    fn malformed_alert_entries_are_rejected() {
        for (yaml, expect) in [
            ("[{post: 1}]", "must be a map"),
            ("[{post: {}, debug: {}}]", "one alert name"),
            ("[5]", "names or maps"),
            ("[{post: null}]", "must be a map"),
        ] {
            let err = load_alert_list("bad", yaml, "").err().unwrap().to_string();
            assert!(err.contains(expect), "{yaml}: {err}");
        }
    }

    #[test]
    fn jira_runs_first_and_the_rest_keeps_its_order() {
        let dir = std::env::temp_dir().join(format!("ea-rule-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("order.yaml");
        std::fs::write(&file, "name: order\ntype: any\nindex: logs-*\nalert: [debug, email, jira, slack]\n").unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        assert_eq!(load(&file, &conf).unwrap().alerts, ["jira", "debug", "email", "slack"]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn active_hours_is_validated() {
        let r = load_text("ah_ok", "active_hours:\n  timezone: Europe/Paris\n  windows:\n  - {days: [mon, fri], from: '08:00', to: '18:30'}\n").unwrap();
        assert!(r.active_hours.is_some());
        assert!(load_text("ah_none", "").unwrap().active_hours.is_none());
        let err = load_text("ah_bad", "active_hours:\n  timezone: Nowhere/City\n  windows: [{from: '08:00', to: '09:00'}]\n").err().unwrap();
        assert!(format!("{err:#}").contains("active_hours"), "{err:#}");
    }

    #[test]
    fn limit_execution_is_validated() {
        let r = load_text("le_ok", "limit_execution: \"* 10-18 * * 1-5\"\nlimit_execution_coverage: true\n").unwrap();
        assert_eq!(r.limit_execution.as_deref(), Some("* 10-18 * * 1-5"));
        assert!(r.limit_execution_coverage);
        assert!(load_text("le_off", "limit_execution: false\n").unwrap().limit_execution.is_none());
        let err = load_text("le_bad", "limit_execution: not a cron\n").err().unwrap();
        assert!(format!("{err:#}").contains("limit_execution"), "{err:#}");
    }

    #[test]
    fn enhancements_and_jinja_filters() {
        let r = load_text("me_ok", "match_enhancements: [TimeEnhancement]\nrun_enhancements_first: true\njinja_filters: []\n").unwrap();
        assert_eq!(r.enhancements.len(), 1);
        assert!(r.run_enhancements_first);
        assert!(load_text("me_bad", "match_enhancements: [my.mod.Class]\n").is_err());
        let r = load_text("me_rust", "match_enhancements:\n- rust.drop_if: {field: user.name, equals: svc}\n- TimeEnhancement\n").unwrap();
        assert_eq!(r.enhancements.len(), 2);
        assert!(load_text("jf_bad", "jinja_filters: [filters.domain.DomainFilters]\n").is_err());
    }

    #[test]
    fn terms_files_become_filters_and_are_hashed() {
        let dir = std::env::temp_dir().join(format!("ea-terms-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ips.txt"), "# bad\n10.0.0.1\n\n 10.0.0.0/8 \n10.0.0.1\n").unwrap();
        let rule = |extra: &str| {
            let file = dir.join("r.yaml");
            std::fs::write(&file, format!("name: tf\ntype: any\nindex: logs-*\nalert: debug\nfilter:\n- term: {{a: 1}}\n{extra}")).unwrap();
            let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
            (load(&file, &conf), file_hash(&file, &conf))
        };
        let (r, h1) = rule("filter_terms_file: {field: source.ip, path: ips.txt}\n");
        assert_eq!(r.unwrap().filter[1], json!({"terms": {"source.ip": ["10.0.0.0/8", "10.0.0.1"]}}));
        let (r, _) = rule("filter_terms_file:\n- {field: source.ip, path: ips.txt, negate: true}\n");
        assert_eq!(r.unwrap().filter[1]["bool"]["must_not"][0]["terms"]["source.ip"][1], json!("10.0.0.1"));
        std::fs::write(dir.join("ips.txt"), "10.0.0.2\n").unwrap();
        let (_, h2) = rule("filter_terms_file: {field: source.ip, path: ips.txt}\n");
        assert_ne!(h1, h2, "a change of the list reloads the rule");
        assert!(rule("filter_terms_file: {field: source.ip, path: nope.txt}\n").0.is_err());
        assert!(rule("filter_terms_file: {field: source.ip}\n").0.is_err());
        assert!(rule("filter_terms_file: {field: f, path: ips.txt, nope: 1}\n").0.is_err());
        std::fs::write(dir.join("ips.txt"), "# nothing\n").unwrap();
        assert!(rule("filter_terms_file: {field: f, path: ips.txt}\n").0.is_err());
        std::fs::write(dir.join("ips.txt"), (0..65_537).map(|i| format!("v{i}\n")).collect::<String>()).unwrap();
        assert!(rule("filter_terms_file: {field: f, path: ips.txt}\n").0.is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn search_options() {
        let r = load_text("so_none", "").unwrap();
        assert_eq!((r.search_timeout, r.terminate_after, r.search_params.as_str()), (None, None, ""));
        let r = load_text("so_ok", "search_timeout: {seconds: 20}\nterminate_after: 5000\npreference: _local\nrouting: 'a b'\n").unwrap();
        assert_eq!((r.search_timeout, r.terminate_after), (Some(20 * SECOND), Some(5000)));
        assert_eq!(r.search_params, "&preference=_local&routing=a+b");
        assert!(load_text("so_zero", "terminate_after: 0\n").is_err());
        assert!(load_text("so_empty", "routing: ''\n").is_err());
    }

    #[test]
    fn eql_and_esql_filters() {
        let r = load_text("eql_ok", "filter:\n- eql: 'process where process.name == \"x\"'\n").unwrap();
        assert_eq!(r.query_lang, Some(QueryLang::Eql));
        assert!(!r.enrich);
        let r = load_text("esql_ok", "max_query_size: 50\nfilter:\n- esql: 'FROM logs-* | WHERE a > 1'\n").unwrap();
        assert_eq!(r.query_lang, Some(QueryLang::Esql));
        assert_eq!(r.filter[0]["esql"], json!("FROM logs-* | WHERE a > 1\n| limit 50"));
        assert!(load_text("eql_count", "use_count_query: true\ndoc_type: x\nfilter:\n- eql: 'any where true'\n").is_err());
        assert!(load_text("both", "filter:\n- eql: 'any where true'\n- esql: 'FROM x'\n").is_err());
        assert_eq!(load_text("plain", "filter:\n- term: {a: 1}\n").unwrap().query_lang, None);
    }

    #[test]
    fn discover_options_are_validated() {
        let r = load_text("kb_ok", "generate_kibana_discover_url: true\nkibana_discover_app_url: x\nkibana_discover_index_pattern_id: y\nkibana_discover_from_timedelta: {minutes: 5}\n").unwrap();
        assert!(r.kibana_discover && !r.opensearch_discover);
        assert!(load_text("kb_bad", "generate_kibana_discover_url: true\nkibana_discover_from_timedelta: {parsecs: 5}\n").is_err());
        assert!(load_text("os_bad", "generate_opensearch_discover_url: true\nopensearch_discover_columns: []\n").is_err());
    }
}
