//! CPU, memory and run time per rule, and the daemon's overall state: read from the daemon's Prometheus endpoint
//! (`--prometheus_port`) and from the `_status` index.

use crate::{App, error::{ApiError, Res}, rules};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use utoipa::{IntoParams, ToSchema};

type S = State<Arc<App>>;

pub struct Sample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// `name{k="v",…} value [timestamp]`; label values may contain `\\`, `\"` and `\n`.
fn parse_line(line: &str) -> Option<Sample> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line.find(['{', ' '])?;
    let name = line[..end].to_string();
    let mut labels = BTreeMap::new();
    let mut rest = &line[end..];
    if let Some(mut r) = rest.strip_prefix('{') {
        loop {
            r = r.trim_start_matches([',', ' ']);
            if let Some(after) = r.strip_prefix('}') {
                rest = after;
                break;
            }
            let (key, after) = r.split_once("=\"")?;
            let (mut val, mut chars) = (String::new(), after.char_indices());
            let close = loop {
                match chars.next()? {
                    (i, '"') => break i,
                    (_, '\\') => match chars.next()?.1 {
                        'n' => val.push('\n'),
                        c => val.push(c),
                    },
                    (_, c) => val.push(c),
                }
            };
            labels.insert(key.to_string(), val);
            r = &after[close + 1..];
        }
    }
    let value = rest.split_whitespace().next()?.parse().ok()?;
    Some(Sample { name, labels, value })
}

pub fn parse(text: &str) -> Vec<Sample> {
    text.lines().filter_map(parse_line).collect()
}

async fn fetch(app: &App) -> Res<Vec<Sample>> {
    let url = app.cfg.metrics_url.as_deref().ok_or_else(|| {
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "ELASTALERT_METRICS_URL is not set: start the daemon with --prometheus_port and point it there")
    })?;
    let text = async { app.http.get(url).send().await?.error_for_status()?.text().await }
        .await
        .map_err(|e| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, format!("daemon metrics at {url} unreachable: {e}")))?;
    Ok(parse(&text))
}

#[derive(Serialize, ToSchema, Default, Clone)]
pub struct RuleStats {
    pub rule_name: String,
    /// Rule file, when a file of the rules folder has this name.
    pub path: Option<String>,
    /// CPU time used by the runs of the rule since the daemon started.
    pub cpu_seconds: f64,
    /// Memory the rule holds now (state kept between runs included).
    pub memory_bytes: u64,
    /// Total time spent evaluating the rule.
    pub time_taken_seconds: f64,
    /// Number of runs.
    pub runs: u64,
    /// `time_taken_seconds / runs`.
    pub avg_run_seconds: Option<f64>,
    pub hits: u64,
    pub matches: u64,
    pub alerts_sent: u64,
    pub alerts_not_sent: u64,
    pub alerts_silenced: u64,
    /// Seconds between now and the end of the last query range.
    pub lag_seconds: Option<f64>,
    /// Unix time of the last run without error.
    pub last_success: Option<f64>,
}

fn per_rule(samples: &[Sample]) -> BTreeMap<String, RuleStats> {
    let mut m: BTreeMap<String, RuleStats> = BTreeMap::new();
    for s in samples {
        let Some(rule) = s.labels.get("rule_name") else { continue };
        let r = m.entry(rule.clone()).or_insert_with(|| RuleStats { rule_name: rule.clone(), ..Default::default() });
        match s.name.as_str() {
            "elastalert_rule_cpu_seconds_total" => r.cpu_seconds = s.value,
            "elastalert_rule_memory_bytes" => r.memory_bytes = s.value as u64,
            "elastalert_time_taken_total" => r.time_taken_seconds = s.value,
            "elastalert_scrapes_total" => r.runs = s.value as u64,
            "elastalert_hits_total" => r.hits = s.value as u64,
            "elastalert_matches_total" => r.matches = s.value as u64,
            "elastalert_alerts_sent_total" => r.alerts_sent = s.value as u64,
            "elastalert_alerts_not_sent_total" => r.alerts_not_sent = s.value as u64,
            "elastalert_alerts_silenced_total" => r.alerts_silenced = s.value as u64,
            "elastalert_rule_lag_seconds" => r.lag_seconds = Some(s.value),
            "elastalert_rule_last_success_timestamp_seconds" => r.last_success = Some(s.value),
            _ => {}
        }
    }
    for r in m.values_mut() {
        r.avg_run_seconds = (r.runs > 0).then(|| r.time_taken_seconds / r.runs as f64);
    }
    m
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    /// `cpu` (default), `memory`, `time` (total), `avg_time`, `lag`, `hits`, `matches`, `alerts`.
    pub sort: Option<String>,
    /// Number of rules (default 50, max 1000).
    pub limit: Option<usize>,
}

fn key(s: &str, r: &RuleStats) -> f64 {
    match s {
        "memory" => r.memory_bytes as f64,
        "time" => r.time_taken_seconds,
        "avg_time" => r.avg_run_seconds.unwrap_or(0.0),
        "lag" => r.lag_seconds.unwrap_or(0.0),
        "hits" => r.hits as f64,
        "matches" => r.matches as f64,
        "alerts" => r.alerts_sent as f64,
        _ => r.cpu_seconds,
    }
}

#[utoipa::path(get, path = "/rules/stats", params(StatsQuery), tag = "stats",
    description = "CPU, memory and run time per rule, the most expensive first. Read from the daemon's Prometheus endpoint.",
    responses((status = 200, body = Vec<RuleStats>), (status = 503, description = "Daemon metrics unreachable")))]
pub async fn rules_stats(State(app): S, Query(q): Query<StatsQuery>) -> Res<Json<Vec<RuleStats>>> {
    let mut stats: Vec<RuleStats> = per_rule(&fetch(&app).await?).into_values().collect();
    let sort = q.sort.unwrap_or_else(|| "cpu".into());
    stats.sort_by(|a, b| key(&sort, b).total_cmp(&key(&sort, a)));
    stats.truncate(q.limit.unwrap_or(50).min(1000));
    let paths: BTreeMap<String, String> = rules::scan(&app).await?.into_iter().map(|r| (r.name, r.path)).collect();
    for s in &mut stats {
        s.path = paths.get(&s.rule_name).cloned();
    }
    Ok(Json(stats))
}

#[derive(Serialize, ToSchema)]
pub struct RuleDetail {
    #[serde(flatten)]
    pub stats: RuleStats,
    /// The last runs from the `_status` index: query range, hits, matches, `time_taken`.
    #[schema(value_type = Vec<Object>)]
    pub recent_runs: Vec<Value>,
}

#[utoipa::path(get, path = "/rules/{path}/stats", tag = "stats",
    params(("path" = String, Path, description = "Rule path, URL-encoded")),
    responses((status = 200, body = RuleDetail), (status = 404, description = "No such rule, or the daemon has not run it yet"), (status = 503)))]
pub async fn rule_stats(State(app): S, Path(rel): Path<String>) -> Res<Json<RuleDetail>> {
    let rule = rules::scan(&app).await?.into_iter().find(|r| r.path == rel).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no such rule"))?;
    let mut stats = per_rule(&fetch(&app).await?)
        .remove(&rule.name)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "the daemon has no metrics for this rule (disabled, invalid or not loaded yet)"))?;
    stats.path = Some(rule.path);
    let runs = app
        .es
        .search(
            &format!("{}_status", app.cfg.wb),
            json!({"query": {"term": {"rule_name": rule.name}}, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], "size": 10}),
        )
        .await?;
    Ok(Json(RuleDetail { stats, recent_runs: runs["items"].as_array().cloned().unwrap_or_default() }))
}

#[derive(Serialize, ToSchema)]
pub struct Status {
    /// The daemon's Prometheus endpoint answered.
    pub metrics_reachable: bool,
    pub rules_loaded: usize,
    /// Errors the daemon counted since it started.
    pub errors_total: Option<f64>,
    pub max_lag_seconds: Option<f64>,
    /// Rules that have not completed a run yet.
    pub rules_never_succeeded: usize,
    pub cpu_seconds_total: f64,
    pub memory_bytes_total: u64,
    /// Elasticsearch requests of the daemon by kind: count, errors, average seconds.
    #[schema(value_type = Object)]
    pub elasticsearch_requests: Value,
    /// Time of the newest document of the `_status` index.
    pub last_run: Option<String>,
    /// Alerts not delivered yet.
    pub pending_alerts: u64,
    /// Documents of the `_error` index in the last hour.
    pub errors_last_hour: u64,
}

#[utoipa::path(get, path = "/status", tag = "stats",
    description = "State of the daemon: rules loaded, lag, errors, Elasticsearch latency, last run, pending alerts. Works without the metrics endpoint, with what the writeback index shows.",
    responses((status = 200, body = Status)))]
pub async fn status(State(app): S) -> Res<Json<Status>> {
    let samples = fetch(&app).await.ok();
    let rules = samples.as_deref().map(per_rule).unwrap_or_default();
    let mut es_req: BTreeMap<String, (f64, f64, f64)> = BTreeMap::new();
    let mut errors_total = None;
    for s in samples.iter().flatten() {
        let kind = s.labels.get("kind").cloned();
        match (s.name.as_str(), kind) {
            ("elastalert_es_request_duration_seconds_count", Some(k)) => es_req.entry(k).or_default().0 = s.value,
            ("elastalert_es_request_duration_seconds_sum", Some(k)) => es_req.entry(k).or_default().1 = s.value,
            ("elastalert_es_request_errors_total", Some(k)) => es_req.entry(k).or_default().2 = s.value,
            ("elastalert_errors_total", None) => errors_total = Some(s.value),
            _ => {}
        }
    }
    let total = |r: Value| r["total"].as_u64().unwrap_or(0);
    let last = app.es.search(&format!("{}_status", app.cfg.wb), json!({"sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}], "size": 1, "_source": ["@timestamp"]})).await?;
    let pending = app.es.search(&app.cfg.wb, json!({"query": {"term": {"alert_sent": false}}, "size": 0})).await?;
    let errors = app.es.search(&format!("{}_error", app.cfg.wb), json!({"query": {"range": {"@timestamp": {"gte": "now-1h"}}}, "size": 0})).await?;
    Ok(Json(Status {
        metrics_reachable: samples.is_some(),
        rules_loaded: rules.len(),
        errors_total,
        max_lag_seconds: rules.values().filter_map(|r| r.lag_seconds).max_by(f64::total_cmp),
        rules_never_succeeded: rules.values().filter(|r| r.last_success.is_none()).count(),
        cpu_seconds_total: rules.values().map(|r| r.cpu_seconds).sum(),
        memory_bytes_total: rules.values().map(|r| r.memory_bytes).sum(),
        elasticsearch_requests: json!(es_req.into_iter().map(|(k, (n, sum, err))| (k, json!({"count": n, "errors": err, "avg_seconds": if n > 0.0 { sum / n } else { 0.0 }}))).collect::<BTreeMap<_, _>>()),
        last_run: last["items"][0]["@timestamp"].as_str().map(str::to_string),
        pending_alerts: total(pending),
        errors_last_hour: total(errors),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prometheus_text() {
        let text = "# HELP x y\n# TYPE x counter\n\
            elastalert_hits_total{rule_name=\"a\\\"b\\\\c\"} 12\n\
            elastalert_rule_cpu_seconds_total{rule_name=\"r\"} 1.5\n\
            elastalert_errors_total 3\n\
            elastalert_es_request_duration_seconds_count{kind=\"search\"} 4 1700000000\n\
            elastalert_scrapes_total{rule_name=\"r\"} 3\n\
            elastalert_time_taken_total{rule_name=\"r\"} 1.5\n";
        let s = parse(text);
        assert_eq!(s.len(), 6);
        assert_eq!(s[0].labels["rule_name"], "a\"b\\c");
        assert_eq!(s[0].value, 12.0);
        assert_eq!(s[2].labels.len(), 0);
        assert_eq!(s[3].value, 4.0);
        let m = per_rule(&s);
        assert_eq!(m["r"].avg_run_seconds, Some(0.5));
        assert_eq!(m["r"].cpu_seconds, 1.5);
        assert_eq!(m["a\"b\\c"].hits, 12);
    }
}
