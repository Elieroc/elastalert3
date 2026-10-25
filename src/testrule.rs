//! `elastalert test-rule` and `elastalert validate`.

use crate::config::Config;
use crate::engine::{Ctx, RuleState, Silences};
use crate::es::Es;
use crate::field;
use crate::metrics::Metrics;
use crate::rule;
use crate::time::{Dur, SECOND, Ts, now, parse_iso};
use crate::types::parse_ts;
use crate::writeback::Writeback;
use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(clap::Args)]
pub struct TestRuleArgs {
    /// Rule file to test
    file: PathBuf,
    /// Only check the rule loads; do not query
    #[arg(long)]
    schema_only: bool,
    /// Query the previous N days (default: the rule's timeframe, else 1 day)
    #[arg(long, default_value_t = 0)]
    days: u32,
    /// Start of the range, ISO timestamp
    #[arg(long)]
    start: Option<String>,
    /// End of the range, ISO timestamp (default: now)
    #[arg(long)]
    end: Option<String>,
    /// Stop right after the first error
    #[arg(long)]
    stop_error: bool,
    /// Print the results as one JSON document
    #[arg(long)]
    formatted_output: bool,
    /// Run against a JSON file of documents instead of Elasticsearch
    #[arg(long, value_name = "FILENAME")]
    data: Option<PathBuf>,
    /// Send real alerts instead of printing them
    #[arg(long)]
    alert: bool,
    /// Save the documents of the range to this file
    #[arg(long, value_name = "FILENAME")]
    save_json: Option<PathBuf>,
    /// Test against the file written by --save-json
    #[arg(long)]
    use_downloaded: bool,
    /// Maximum number of documents to download
    #[arg(long, default_value_t = 10_000)]
    max_query_size: u64,
    /// Only show how many documents match the filter
    #[arg(long)]
    count_only: bool,
}

fn fail(code: i32, msg: String) -> ! {
    eprintln!("{msg}");
    std::process::exit(code);
}

/// Dotted names of every leaf field (nested objects are flattened).
fn print_terms(doc: &Map<String, Value>, parent: &str, out: &mut Vec<String>) {
    for (k, v) in doc {
        match v {
            Value::Object(m) => print_terms(m, &format!("{parent}{k}."), out),
            _ => out.push(format!("{parent}{k}")),
        }
    }
}

/// Checks every rule file, reports each problem, exit code 1 if any.
pub async fn validate(conf: &Config, with_es: bool) -> Result<()> {
    let files = rule::discover(conf, None)?;
    let (mut ok, mut bad) = (0, 0);
    let mut names: Vec<String> = Vec::new();
    let mut loaded = Vec::new();
    for f in &files {
        match rule::load(f, conf).and_then(|r| {
            if names.contains(&r.name) {
                anyhow::bail!("duplicate rule name {}", r.name);
            }
            names.push(r.name.clone());
            RuleState::new(r.clone()).map(|_| loaded.push(r))
        }) {
            Ok(()) => ok += 1,
            Err(e) => {
                bad += 1;
                println!("{}: {e:#}", f.display());
            }
        }
    }
    println!("{ok} rule(s) valid, {bad} invalid");
    if with_es {
        let es = Es::from_conf(&conf.raw)?;
        let warnings = crate::lint::check_rules(&es, &loaded).await;
        println!("{warnings} warning(s) from Elasticsearch");
    }
    if bad > 0 {
        std::process::exit(1);
    }
    Ok(())
}

pub async fn run(args: TestRuleArgs, config: &Path) -> Result<()> {
    let conf = Config::load_with_defaults(config)?;
    let rule = match rule::load(&args.file, &conf) {
        Ok(r) => r,
        Err(e) => fail(3, format!("Invalid rule file: {e:#}")),
    };
    if args.schema_only {
        println!("{}: OK", args.file.display());
        return Ok(());
    }
    let es = Es::from_conf(&conf.raw)?;
    let mut formatted = Map::new();
    let ts_field = rule.timestamp_field.clone();

    // Time range
    let endtime: Ts = match &args.end {
        Some(e) => parse_iso(e).with_context(|| format!("Input is not a valid ISO8601 timestamp: {e}"))?,
        None => now(),
    };
    let day: Dur = 86_400 * SECOND;
    let mut starttime: Ts = match (&args.start, args.days, rule.timeframe) {
        (Some(s), ..) => parse_iso(s).with_context(|| format!("Input is not a valid ISO8601 timestamp: {s}"))?,
        (None, d, _) if d > 0 => endtime - d as Dur * day,
        (None, _, Some(tf)) => endtime - (tf as f64 * 1.01) as Dur,
        _ => endtime - day,
    };

    // Data: a file, or Elasticsearch (shows the fields of the first hit, optionally saves the hits)
    let mut data: Option<Vec<Map<String, Value>>> = None;
    if let Some(path) = &args.data {
        data = Some(read_docs(path)?);
    } else {
        let hits = query_es(&args, &rule, &es, starttime, endtime, &mut formatted).await;
        if let (Some(hits), Some(path)) = (&hits, &args.save_json) {
            let docs: Vec<Value> = hits
                .iter()
                .map(|h| {
                    let mut src = h["_source"].as_object().cloned().unwrap_or_default();
                    src.insert("_id".into(), h["_id"].clone());
                    Value::Object(src)
                })
                .collect();
            std::fs::write(path, serde_json::to_string_pretty(&docs)?)?;
        }
        if args.use_downloaded {
            data = Some(match (&args.save_json, hits.as_ref().is_some_and(|h| !h.is_empty())) {
                (Some(path), true) => read_docs(path)?,
                _ => vec![],
            });
        }
        if args.formatted_output
            && let Some(h) = hits
        {
            formatted.insert("results".into(), Value::Array(h));
        }
    }
    if args.count_only {
        return Ok(());
    }

    // Run the rule
    if let Some(docs) = &mut data {
        if docs.is_empty() {
            if args.formatted_output {
                println!("{}", Value::Object(formatted));
            }
            return Ok(());
        }
        let mut stamped: Vec<(Ts, usize)> = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            match field::lookup(d, &ts_field).and_then(|v| parse_ts(&rule, v)) {
                Some(t) => stamped.push((t, i)),
                None if args.stop_error => fail(4, "All documents must have a timestamp".into()),
                None => return Ok(()),
            }
        }
        stamped.sort();
        starttime = stamped[0].0;
        let last = stamped[stamped.len() - 1].0 + SECOND;
        for (n, d) in docs.iter_mut().enumerate() {
            d.entry("_id").or_insert_with(|| json!(format!("mock-{n}")));
        }
        docs.sort_by_key(|d| field::lookup(d, &ts_field).and_then(|v| parse_ts(&rule, v)));
        run_rule(&args, &conf, rule, es, Some(docs.clone()), starttime, last, &mut formatted).await?;
    } else {
        run_rule(&args, &conf, rule, es, None, starttime, endtime, &mut formatted).await?;
    }
    if args.formatted_output {
        println!("{}", Value::Object(formatted));
    }
    Ok(())
}

fn read_docs(path: &Path) -> Result<Vec<Map<String, Value>>> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)?;
    Ok(match v {
        Value::Array(a) => a.into_iter().filter_map(|x| x.as_object().cloned()).collect(),
        Value::Object(o) => vec![o],
        _ => vec![],
    })
}

/// Shows hit count and the fields of one document; returns up to `max_query_size` hits when they are needed.
async fn query_es(args: &TestRuleArgs, rule: &rule::Rule, es: &Es, start: Ts, end: Ts, formatted: &mut Map<String, Value>) -> Option<Vec<Value>> {
    if let Some(lang) = rule.query_lang {
        // The preview uses plain searches and counts; an EQL / ES|QL rule goes straight to the run below.
        println!("Skipping the hit count preview: {} queries are run as part of the rule.", lang.key());
        return None;
    }
    let st = RuleState::new_for_query(rule);
    let index = match st.index_for(start, end) {
        Ok(i) => i,
        Err(e) => fail(3, format!("Invalid rule file: {e:#}")),
    };
    let mut body = st.query(start, end);
    body.as_object_mut().map(|b| b.remove("_source"));
    let one = es.search(&index, &json!({"query": body["query"], "sort": body["sort"], "size": 1})).await;
    let res = match one {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error running your filter:\n{e:#}");
            if args.stop_error {
                std::process::exit(2);
            }
            return None;
        }
    };
    let days = args.days;
    let Some(first) = res["hits"]["hits"].get(0) else {
        println!("Didn't get any results.");
        return Some(vec![]);
    };
    let terms = first["_source"].as_object().cloned().unwrap_or_default();
    let count = match es.count(&index, &json!({"query": body["query"]})).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error querying Elasticsearch:\n{e:#}");
            if args.stop_error {
                std::process::exit(2);
            }
            return None;
        }
    };
    if args.formatted_output {
        let mut names = Vec::new();
        print_terms(&terms, "", &mut names);
        formatted.insert("hits".into(), json!(count));
        formatted.insert("days".into(), json!(days));
        formatted.insert("terms".into(), json!(terms.keys().collect::<Vec<_>>()));
        formatted.insert("result".into(), Value::Object(terms.clone()));
    } else {
        println!("Got {count} hits from the last {days} day{}", if days > 1 { "s" } else { "" });
        println!("\nAvailable terms in first hit:");
        let mut names = Vec::new();
        print_terms(&terms, "", &mut names);
        names.iter().for_each(|n| println!("\t{n}"));
    }
    for key in rule.compare_key.iter().chain(rule.query_key.iter()) {
        if field::lookup(&terms, key).is_none() {
            eprintln!("Warning: key {key} is either missing or null!");
        }
    }
    for t in &rule.top_count_keys {
        let plain = t.strip_suffix(".keyword").unwrap_or(t);
        if field::lookup(&terms, plain).is_none() {
            eprintln!("top_count_key {t} may be missing");
        }
    }
    if !args.formatted_output {
        println!();
    }
    if (args.save_json.is_some() || args.formatted_output) && !args.count_only {
        let full = json!({"query": body["query"], "sort": body["sort"], "size": args.max_query_size});
        return match es.search(&index, &full).await {
            Ok(r) => {
                let hits = r["hits"]["hits"].as_array().cloned().unwrap_or_default();
                if args.save_json.is_some() {
                    println!("Downloaded {} documents to save", hits.len());
                }
                Some(hits)
            }
            Err(e) => {
                eprintln!("Error running your filter:\n{e:#}");
                if args.stop_error {
                    std::process::exit(2);
                }
                None
            }
        };
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn run_rule(
    args: &TestRuleArgs,
    conf: &Config,
    mut rule: rule::Rule,
    es: Es,
    mock: Option<Vec<Map<String, Value>>>,
    start: Ts,
    end: Ts,
    formatted: &mut Map<String, Value>,
) -> Result<()> {
    // One query covers the whole range unless the rule queries per run_every anyway.
    if !(rule.use_count_query || rule.use_terms_query) {
        rule.buffer_time = (end - start).max(SECOND);
    }
    let mut st = RuleState::new(rule)?;
    st.mock = mock;
    let (wb, captured) = Writeback::capturing(conf.writeback_index.clone());
    let ctx = Ctx {
        es,
        writeback: wb,
        silences: Arc::new(Silences::default()),
        metrics: Arc::new(Metrics::default()),
        notifier: None,
        debug: !args.alert,
        disabled: Default::default(),
        disable_rules_on_error: false,
        run_every: conf.run_every,
        use_pit: conf.raw.get("use_pit").and_then(Value::as_bool).unwrap_or(true),
        old_query_limit: conf.old_query_limit,
        alert_time_limit: conf.alert_time_limit,
        scroll_keepalive: conf.scroll_keepalive.clone(),
        ts_fmt: conf.custom_pretty_ts_format.clone(),
    };
    let result = st.run(&ctx, end, Some(start)).await;
    st.flush_due(&ctx, true).await;
    if let Err(e) = result {
        eprintln!("Error running rule: {e:#}");
        if args.stop_error {
            std::process::exit(2);
        }
    }
    let docs = captured.lock().unwrap().clone();
    if !docs.is_empty() {
        if args.formatted_output {
            let mut wbk = Map::new();
            for (index, doc) in &docs {
                wbk.insert(index.clone(), doc.clone());
            }
            formatted.insert("writeback".into(), Value::Object(wbk));
        } else {
            println!("\nWould have written the following documents to writeback index (default is elastalert_status):\n");
            for (index, doc) in &docs {
                println!("{index} - {doc}\n");
            }
        }
        if args.stop_error && docs.iter().any(|(i, _)| i.ends_with("_error")) {
            std::process::exit(2);
        }
    }
    Ok(())
}
