mod alert;
mod alerters;
mod config;
mod correlation;
mod discover;
mod engine;
mod enhancements;
mod exceptions;
mod es;
mod field;
mod hours;
mod index;
mod lint;
mod metrics;
mod mitre;
mod notify;
mod querylang;
mod rule;
mod setup;
mod sigma;
mod testrule;
mod time;
mod types;
mod writeback;

use anyhow::{Context, Result, bail};
use futures_util::FutureExt;
use clap::{Parser, Subcommand};
use config::Config;
use engine::{Ctx, Pending, RuleState, Silences};
use metrics::Metrics;
use es::Es;
use rustc_hash::FxHashMap;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::{Ts, now, parse_iso, to_iso};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use writeback::Writeback;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// ElastAlert-compatible alerting daemon for Elasticsearch / OpenSearch.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Global config file
    #[arg(long, default_value = "config.yaml", global = true)]
    config: PathBuf,
    /// Log alerts instead of sending them; nothing is written to ES
    #[arg(long)]
    debug: bool,
    /// Log at info level without suppressing alerts
    #[arg(long)]
    verbose: bool,
    /// Run only this rule (file name inside the rules folder, or a path)
    #[arg(long)]
    rule: Option<String>,
    /// Silence the rule for a period, e.g. hours=2 (needs --rule)
    #[arg(long)]
    silence: Option<String>,
    /// Silence only this query_key value
    #[arg(long = "silence_qk_value")]
    silence_qk_value: Option<String>,
    /// Start querying from this ISO timestamp, or NOW
    #[arg(long)]
    start: Option<String>,
    /// Query up to this ISO timestamp, then exit
    #[arg(long)]
    end: Option<String>,
    /// Wait up to this long for ES and the writeback index, e.g. minutes=5
    #[arg(long = "patience")]
    patience: Option<String>,
    /// Do not reload rule files when they change
    #[arg(long = "pin_rules")]
    pin_rules: bool,
    /// Log every request sent to Elasticsearch
    #[arg(long = "es_debug")]
    es_debug: bool,
    /// Append every Elasticsearch request, as a curl command with its response, to this file
    #[arg(long = "es_debug_trace", value_name = "FILE")]
    es_debug_trace: Option<PathBuf>,
    /// Serve Prometheus metrics on this port
    #[arg(long = "prometheus_port")]
    prometheus_port: Option<u16>,
    /// Address to bind the Prometheus metrics server on
    #[arg(long = "prometheus_addr", default_value = "0.0.0.0")]
    prometheus_addr: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the writeback indices (with the mappings the daemon relies on)
    CreateIndex {
        /// Index name (default: writeback_index from the config)
        #[arg(long)]
        index: Option<String>,
        /// Copy the data of this existing index into the new one
        #[arg(long = "old-index")]
        old_index: Option<String>,
        /// Delete and recreate existing indices (data loss)
        #[arg(long)]
        recreate: bool,
    },
    /// Run one rule over past data without alerting, and show what it would do
    TestRule(testrule::TestRuleArgs),
    /// Load the config and every rule (including alerter options) and report errors; no Elasticsearch needed
    Validate {
        /// Also check the fields and filters of each rule against the mappings of its indices, and have Elasticsearch parse the filters
        #[arg(long)]
        es: bool,
    },
    /// Write an ATT&CK Navigator layer of the techniques the rules cover (mitre_attack); no Elasticsearch needed
    MitreLayer(mitre::LayerArgs),
    /// Print the ElastAlert options a Sigma rule compiles to; no Elasticsearch and no config needed
    SigmaConvert(sigma::ConvertArgs),
}

struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= self.0 || (m.target() == "elasticsearch" && m.level() <= log::max_level())
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            let name = if r.target() == "elasticsearch" { "elasticsearch" } else { "elastalert" };
            eprintln!("{}:{name}:{}", r.level().as_str().replace("WARN", "WARNING"), r.args());
        }
    }
    fn flush(&self) {}
}

fn parse_time_arg(s: &str) -> Result<Ts> {
    if s == "NOW" {
        return Ok(now());
    }
    parse_iso(s).with_context(|| format!("{s} is not a valid ISO8601 timestamp (YYYY-MM-DDTHH:MM:SS+XX:00)"))
}

async fn wait_until_responsive(es: &Es, index: &str, patience: time::Dur) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_micros(patience as u64);
    while std::time::Instant::now() < deadline {
        if es.exists(index).await.unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("writeback index \"{index}\" not reachable; is ES up and did you run `elastalert create-index`?")
}

/// `--silence`: write a silence doc and exit.
async fn silence(args: &Args, rule: &rule::Rule, es: &Es, index: &str) -> Result<()> {
    if args.debug {
        bail!("--silence not compatible with --debug");
    }
    let until = now() + time::parse_duration_arg(args.silence.as_deref().unwrap_or_default())?;
    let key = match &args.silence_qk_value {
        Some(v) => format!("{}.{v}", rule.realert_key),
        None => format!("{}._silence", rule.name),
    };
    let doc = json!({"exponent": 0, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
    es.post(&format!("{index}_silence/_doc?refresh=true"), &doc).await.context("Failed to save silence command to Elasticsearch")?;
    log::info!("Success. {key} will be silenced until {}", to_iso(until));
    Ok(())
}

/// Loads every active silence from ES into memory (startup, then every maintenance tick so that
/// `--silence` from another process takes effect).
async fn refresh_silences(ctx: &Ctx, index: &str) {
    let body = json!({"query": {"range": {"until": {"gt": "now"}}}, "size": 10000});
    match ctx.es.search(&format!("{index}_silence"), &body).await {
        Ok(r) => {
            for h in r["hits"]["hits"].as_array().into_iter().flatten() {
                let s = &h["_source"];
                if let (Some(name), Some(until)) = (s["rule_name"].as_str(), s["until"].as_str().and_then(parse_iso)) {
                    ctx.silences.raise(name, until, s["exponent"].as_i64().unwrap_or(0) as i32);
                }
            }
        }
        Err(e) => log::warn!("Error reading silences from Elasticsearch: {e:#}"),
    }
}

/// Unsent alerts and aggregation groups left in ES by the previous run are put back in their rules.
async fn recover_pending(ctx: &Ctx, index: &str, states: &mut [RuleState]) {
    let body = json!({"query": {"bool": {"filter": [
        {"term": {"alert_sent": false}},
        {"range": {"alert_time": {"gte": to_iso(now() - ctx.alert_time_limit)}}},
    ]}}});
    let hits = match ctx.es.scan(index, &body, "1m").await {
        Ok(h) => h,
        Err(e) => return log::warn!("Error finding recent pending alerts: {e:#}"),
    };
    // Children of an aggregated alert point at the head's _id.
    let mut children: FxHashMap<String, Vec<&Value>> = FxHashMap::default();
    for h in &hits {
        if let Some(head) = h["_source"]["aggregate_id"].as_str() {
            children.entry(head.to_string()).or_default().push(h);
        }
    }
    let (mut alerts, mut groups) = (0, 0);
    for h in hits.iter().filter(|h| h["_source"]["aggregate_id"].is_null()) {
        let s = &h["_source"];
        let (Some(name), Some(body)) = (s["rule_name"].as_str(), s["match_body"].as_object()) else { continue };
        let Some(st) = states.iter_mut().find(|st| st.rule.name == name) else { continue };
        let id = h["_id"].as_str().unwrap_or_default().to_string();
        let alert_time = s["alert_time"].as_str().and_then(parse_iso).unwrap_or_else(now);
        let mut kids: Vec<&&Value> = children.get(&id).into_iter().flatten().collect();
        kids.sort_by_key(|k| k["_source"]["@timestamp"].as_str().and_then(parse_iso));
        let mut matches = vec![body.clone()];
        matches.extend(kids.iter().filter_map(|k| k["_source"]["match_body"].as_object().cloned()));
        let child_ids: Vec<String> = kids.iter().filter_map(|k| k["_id"].as_str().map(String::from)).collect();
        if s.get("alerters_sent").is_some() {
            // A send that failed part way: retry the alerters that did not get it.
            let sent: Vec<&str> = s["alerters_sent"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            st.restore_pending(Pending {
                id,
                matches,
                done: st.rule.alert_labels().iter().map(|k| sent.contains(&k.as_str())).collect(),
                attempts: s["retry_count"].as_u64().unwrap_or(0) as u32,
                next_try: 0,
                alert_time,
                exception: s["alert_exception"].as_str().unwrap_or_default().to_string(),
                child_ids,
            });
            alerts += 1;
        } else if st.rule.aggregation.is_some() {
            // Never sent: an aggregation group still waiting for its time.
            st.restore_group(s["aggregation_key"].as_str().unwrap_or_default().to_string(), id, alert_time, matches, child_ids);
            groups += 1;
        }
    }
    if alerts + groups > 0 {
        log::info!("Recovered {alerts} unsent alert(s) and {groups} aggregation group(s) from the writeback index");
    }
}

/// Runs one rule forever on its `run_every` schedule until `stop` flips; hands the state back.
async fn rule_task(
    mut st: RuleState,
    ctx: Arc<Ctx>,
    sem: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
    mut initial: Option<Ts>,
    first_delay: Duration,
) -> RuleState {
    tokio::select! {
        _ = tokio::time::sleep(first_delay) => {}
        _ = stop.changed() => return st,
    }
    loop {
        let started = tokio::time::Instant::now();
        let mut next = started + Duration::from_micros(st.rule.run_every.max(time::SECOND) as u64) + Duration::from_millis(pseudo_random(5_000));
        let end = now() - st.rule.query_delay;
        // `limit_execution`: outside the cron window the rule sleeps until the next one; a rule that has not run
        // yet since it was loaded does not run at all in that case.
        let pause = st.limit_check(end);
        if pause.is_none() || st.has_run_once {
            st.has_run_once = true;
            let _permit = sem.acquire().await;
            let end = now() - st.rule.query_delay;
            let outcome = std::panic::AssertUnwindSafe(st.run(&ctx, end, initial.take())).catch_unwind().await;
            match outcome {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    ctx.metrics.error();
                    ctx.writeback.error(format!("Error running rule {}: {e:#}", st.rule.name), json!({"rule": st.rule.name})).await;
                }
                Err(panic) => {
                    // A bug, not a data or connection problem: upstream calls this an uncaught exception.
                    ctx.metrics.error();
                    let msg = panic.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| panic.downcast_ref::<String>().cloned()).unwrap_or_else(|| "unknown panic".into());
                    let trace = notify::last_panic();
                    ctx.writeback.error_full(format!("Uncaught exception running rule {}: {msg}", st.rule.name), json!({"rule": st.rule.name}), trace.clone(), false).await;
                    if let Some(n) = &ctx.notifier {
                        n.uncaught(&st.rule.name, notify::string_list(st.rule.raw.get("notify_email")), &format!("Uncaught exception running rule {}: {msg}", st.rule.name), &trace.join("\n"));
                    }
                    if ctx.disable_rules_on_error {
                        drop(_permit);
                        ctx.disabled.lock().unwrap().push(st.rule.name.clone());
                        log::info!("Rule {} disabled", st.rule.name);
                        // Parked until the rule file changes (reload stops this task) or the daemon restarts.
                        let _ = stop.changed().await;
                        ctx.disabled.lock().unwrap().retain(|n| *n != st.rule.name);
                        return st;
                    }
                }
            }
        }
        st.forget_old_hits();
        if let Some(until) = pause {
            st.pause(until, ctx.ts_fmt.as_deref());
            next = tokio::time::Instant::now() + Duration::from_micros((until - now()).max(0) as u64);
        } else if tokio::time::Instant::now() > started + Duration::from_micros(st.rule.run_every.max(time::SECOND) as u64) {
            log::warn!("Rule {} took longer than its run_every to process", st.rule.name);
        }
        // Wait for the next run, sending aggregated alerts as soon as their time comes.
        loop {
            st.flush_due(&ctx, false).await;
            let wake = match st.next_agg_due() {
                Some(t) => next.min(tokio::time::Instant::now() + Duration::from_micros((t - now()).max(0) as u64)),
                None => next,
            };
            tokio::select! {
                _ = tokio::time::sleep_until(wake) => {}
                _ = stop.changed() => {
                    // Shutting down or reloading: groups keep their ES docs and come back at startup.
                    return st;
                }
            }
            if tokio::time::Instant::now() >= next {
                break;
            }
        }
    }
}

fn pseudo_random(max_ms: u64) -> u64 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    (nanos as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % max_ms.max(1)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

/// A rule file being watched: its content hash and, unless disabled, its running task.
struct Running {
    hash: u64,
    name: String,
    task: Option<(watch::Sender<bool>, JoinHandle<RuleState>)>,
}

impl Running {
    async fn stop(&mut self) -> Option<RuleState> {
        let (tx, handle) = self.task.take()?;
        let _ = tx.send(true);
        handle.await.ok()
    }
}

struct Runtime {
    ctx: Arc<Ctx>,
    sem: Arc<Semaphore>,
    running: FxHashMap<PathBuf, Running>,
}

impl Runtime {
    fn spawn(&mut self, st: RuleState, initial: Option<Ts>, delay: Duration) -> (watch::Sender<bool>, JoinHandle<RuleState>) {
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(rule_task(st, self.ctx.clone(), self.sem.clone(), rx, initial, delay));
        (tx, h)
    }

    /// Syncs running rules with the files on disk: removed -> stop, changed -> reload keeping state, new -> start.
    async fn reload(&mut self, conf: &Config, only: Option<&str>) {
        let files = match rule::discover(conf, only) {
            Ok(f) => f,
            Err(e) => return log::error!("Error scanning rules folder: {e:#}"),
        };
        let current: FxHashMap<PathBuf, u64> = files.into_iter().map(|f| (rule::file_hash(&f, conf), f)).map(|(h, f)| (f, h)).collect();
        let gone: Vec<PathBuf> = self.running.keys().filter(|p| !current.contains_key(*p)).cloned().collect();
        for path in gone {
            log::info!("Rule file {} not found, stopping rule execution", path.display());
            if let Some(mut r) = self.running.remove(&path) {
                r.stop().await;
            }
        }
        for (path, hash) in current {
            if self.running.get(&path).is_some_and(|r| r.hash == hash) {
                continue;
            }
            let is_new = !self.running.contains_key(&path);
            let loaded = rule::load(&path, conf).and_then(|r| {
                if self.running.iter().any(|(p, x)| *p != path && x.name == r.name) {
                    bail!("A rule with the name {} already exists", r.name);
                }
                Ok(r)
            });
            let rule = match loaded {
                Ok(r) => r,
                Err(e) => {
                    self.load_failed(&path, &e).await;
                    match self.running.get_mut(&path) {
                        Some(r) => r.hash = hash, // keep the old version running; don't complain every cycle
                        None => {
                            self.running.insert(path, Running { hash, name: String::new(), task: None });
                        }
                    }
                    continue;
                }
            };
            let name = rule.name.clone();
            if rule.raw.get("is_enabled").and_then(Value::as_bool) == Some(false) {
                log::info!("Rule file {} is now disabled.", path.display());
                if let Some(mut r) = self.running.remove(&path) {
                    r.stop().await;
                }
                self.running.insert(path, Running { hash, name, task: None });
                continue;
            }
            let mut st = match RuleState::new(rule) {
                Ok(s) => s,
                Err(e) => {
                    self.load_failed(&path, &e).await;
                    continue;
                }
            };
            if let Some(mut old) = self.running.remove(&path) {
                log::info!("Reloading configuration for rule {}", path.display());
                if let Some(old_state) = old.stop().await {
                    st.carry_over(old_state);
                }
            } else {
                log::info!("Loaded new rule {}", path.display());
            }
            let delay = if is_new { Duration::from_millis(pseudo_random(15_000)) } else { Duration::ZERO };
            let task = self.spawn(st, None, delay);
            self.running.insert(path, Running { hash, name, task: Some(task) });
        }
    }

    /// Logs, records and mails a rule file that could not be loaded.
    async fn load_failed(&self, path: &std::path::Path, e: &anyhow::Error) {
        let msg = format!("Could not load rule {}: {e:#}", path.display());
        self.ctx.writeback.error_full(msg.clone(), json!({}), vec![], false).await;
        if let Some(n) = &self.ctx.notifier {
            // The file may still be readable YAML with its own notify_email.
            let extra = rule::load_yaml(path).map(|(r, _)| notify::string_list(r.get("notify_email"))).unwrap_or_default();
            n.rule_load_failed(&path.display().to_string(), extra, &msg);
        }
    }

    async fn stop_all(&mut self) {
        for (_, mut r) in self.running.drain() {
            r.stop().await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = if args.debug || args.verbose || matches!(args.cmd, Some(Cmd::TestRule(_))) { log::LevelFilter::Info } else { log::LevelFilter::Warn };
    log::set_logger(Box::leak(Box::new(Logger(level)))).expect("logger set once");
    log::set_max_level(if args.es_debug { log::LevelFilter::Info } else { level });

    if let Some(Cmd::TestRule(t)) = args.cmd {
        return testrule::run(t, &args.config).await;
    }
    if let Some(Cmd::SigmaConvert(c)) = &args.cmd {
        return sigma::convert_cmd(c);
    }
    let conf = Config::load(&args.config)?;
    if let Some(Cmd::Validate { es }) = &args.cmd {
        return testrule::validate(&conf, *es).await;
    }
    if let Some(Cmd::MitreLayer(m)) = &args.cmd {
        return mitre::layer_cmd(m, &conf);
    }
    let metrics = Arc::new(Metrics::default());
    let es = Es::from_conf(&conf.raw)?.with_tracing(args.es_debug, args.es_debug_trace.as_deref())?.with_metrics(metrics.clone());

    if let Some(Cmd::CreateIndex { index, old_index, recreate }) = &args.cmd {
        let index = index.as_deref().unwrap_or(&conf.writeback_index);
        return setup::create_index(&es, index, *recreate, old_index.as_deref()).await;
    }
    if args.debug {
        log::info!("Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them but remain verbose, use --verbose instead.");
    }

    let rules = rule::load_all(&conf, args.rule.as_deref())?;
    if let (Some(port), false) = (args.prometheus_port, args.debug) {
        metrics::serve(format!("{}:{port}", args.prometheus_addr), metrics.clone()).await?;
    }
    notify::install_panic_hook();
    let notifier = notify::Notifier::from_conf(&conf, &args.config, args.pin_rules)?;
    let notify_all = conf.raw.get("notify_all_errors").and_then(Value::as_bool).unwrap_or(false);
    let (wb, wb_handle) = Writeback::start((!args.debug).then(|| es.clone()), conf.writeback_index.clone());
    let wb = wb.with_notifier(notifier.clone(), notify_all);
    let ctx = Arc::new(Ctx {
        replay: false,
        es: es.clone(),
        writeback: wb,
        silences: Arc::new(Silences::default()),
        metrics: metrics.clone(),
        notifier: notifier.clone(),
        run_every: conf.run_every,
        use_pit: conf.raw.get("use_pit").and_then(Value::as_bool).unwrap_or(true),
        debug: args.debug,
        disabled: Default::default(),
        disable_rules_on_error: conf.raw.get("disable_rules_on_error").and_then(Value::as_bool).unwrap_or(true),
        old_query_limit: conf.old_query_limit,
        alert_time_limit: conf.alert_time_limit,
        scroll_keepalive: conf.scroll_keepalive.clone(),
        ts_fmt: conf.custom_pretty_ts_format.clone(),
    });

    if args.silence.is_some() {
        let Some(rule) = rules.first().filter(|_| args.rule.is_some()) else { bail!("--silence must be used with --rule") };
        return silence(&args, rule, &es, &conf.writeback_index).await;
    }
    if let Some(p) = &args.patience {
        wait_until_responsive(&es, &conf.writeback_index, time::parse_duration_arg(p)?).await?;
    }
    let start = args.start.as_deref().map(parse_time_arg).transpose()?;
    let end = args.end.as_deref().map(parse_time_arg).transpose()?;

    let mut states = Vec::new();
    let mut hashes = Vec::new();
    for r in rules {
        hashes.push((r.file.clone(), rule::file_hash(&r.file, &conf)));
        match RuleState::new(r) {
            Ok(s) => states.push(s),
            Err(e) if conf.skip_invalid => log::error!("Invalid rule skipped: {e:#}"),
            Err(e) => bail!("{e:#}"),
        }
    }
    if !args.debug {
        refresh_silences(&ctx, &conf.writeback_index).await;
        recover_pending(&ctx, &conf.writeback_index, &mut states).await;
    }
    log::info!("Starting up");

    let sem = Arc::new(Semaphore::new(conf.max_threads.max(1)));
    if let Some(end) = end {
        // Bounded replay: one run per rule over [start, end], then exit.
        let mut tasks = tokio::task::JoinSet::new();
        for mut st in states {
            let (ctx, sem) = (ctx.clone(), sem.clone());
            tasks.spawn(async move {
                let _permit = sem.acquire().await;
                if let Err(e) = st.run(&ctx, end, start).await {
                    ctx.writeback.error(format!("Error running rule {}: {e:#}", st.rule.name), json!({"rule": st.rule.name})).await;
                }
                // A replay ends here: aggregated alerts are sent now instead of waiting for their time.
                st.flush_due(&ctx, true).await;
            });
        }
        while tasks.join_next().await.is_some() {}
    } else {
        let mut rt = Runtime { ctx: ctx.clone(), sem, running: FxHashMap::default() };
        for st in states {
            let path = st.rule.file.clone();
            let hash = hashes.iter().find(|(p, _)| *p == path).map_or(0, |(_, h)| *h);
            let name = st.rule.name.clone();
            let task = rt.spawn(st, start, Duration::from_millis(pseudo_random(15_000)));
            rt.running.insert(path, Running { hash, name, task: Some(task) });
        }
        let period = Duration::from_micros(conf.run_every.max(time::SECOND) as u64);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        let stop = shutdown_signal();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = tick.tick() => {
                    if !args.debug {
                        refresh_silences(&ctx, &conf.writeback_index).await;
                    }
                    if conf.raw.get("show_disabled_rules").and_then(Value::as_bool).unwrap_or(true) {
                        let disabled = ctx.disabled.lock().unwrap().clone();
                        if !disabled.is_empty() {
                            log::info!("Disabled rules are: {disabled:?}");
                        }
                    }
                    if !args.pin_rules {
                        rt.reload(&conf, args.rule.as_deref()).await;
                    }
                }
            }
        }
        log::info!("Stopping: finishing running rules and flushing writeback");
        rt.stop_all().await;
    }

    drop(ctx);
    if let Some(h) = wb_handle {
        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
    Ok(())
}
