//! Prometheus metrics (`--prometheus_port`): upstream's names for the per-rule counters, plus rule lag and the
//! duration of Elasticsearch requests. Hand-rolled text exposition, no dependency.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default, Clone)]
pub struct RuleCounters {
    pub scrapes: u64,
    pub hits: u64,
    pub matches: u64,
    pub time_taken: f64,
    pub alerts_sent: u64,
    pub alerts_not_sent: u64,
    pub alerts_silenced: u64,
    /// End of the last successful run, seconds since the epoch.
    pub last_end: Option<f64>,
    /// When that run finished, seconds since the epoch.
    pub last_success: Option<f64>,
}

const BUCKETS: [f64; 12] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

/// Duration of the requests of one kind (`search`, `count`, `pit`, ...).
#[derive(Default)]
struct Histogram {
    /// Requests at most `BUCKETS[i]` seconds, not cumulative.
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
    errors: u64,
}

/// What an Elasticsearch request does, from its path and method: the label of `elastalert_es_request_*`.
pub fn request_kind(method: &str, path: &str) -> &'static str {
    let path = path.split('?').next().unwrap_or(path);
    let has = |s: &str| path.split('/').any(|p| p == s);
    match () {
        _ if has("_pit") => "pit",
        _ if has("scroll") => "scroll",
        _ if has("_eql") => "eql",
        _ if has("_query") && path.starts_with("_query") => "esql",
        _ if has("_validate") => "validate",
        _ if has("_field_caps") => "field_caps",
        _ if has("_search") => "search",
        _ if has("_count") => "count",
        _ if has("_mget") => "mget",
        _ if has("_bulk") => "bulk",
        _ if method == "GET" => "get",
        _ => "other",
    }
}

#[derive(Default)]
pub struct Metrics {
    rules: Mutex<BTreeMap<String, RuleCounters>>,
    errors: AtomicU64,
    es: Mutex<BTreeMap<&'static str, Histogram>>,
}

impl Metrics {
    pub fn rule(&self, name: &str, f: impl FnOnce(&mut RuleCounters)) {
        f(self.rules.lock().unwrap().entry(name.to_string()).or_default());
    }

    /// One Elasticsearch request of `kind` that took `secs`.
    pub fn es_request(&self, kind: &'static str, secs: f64, ok: bool) {
        let mut all = self.es.lock().unwrap();
        let h = all.entry(kind).or_default();
        if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
            h.buckets[i] += 1;
        }
        h.count += 1;
        h.sum += secs;
        h.errors += u64::from(!ok);
    }

    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text format. Counter names end in `_total` like prometheus_client's.
    pub fn render(&self) -> String {
        let rules = self.rules.lock().unwrap();
        let mut out = String::new();
        let mut family = |name: &str, help: &str, value: &dyn Fn(&RuleCounters) -> String| {
            let _ = writeln!(out, "# HELP {name}_total {help}\n# TYPE {name}_total counter");
            for (rule, c) in rules.iter() {
                let _ = writeln!(out, "{name}_total{{rule_name=\"{}\"}} {}", rule.replace('\\', "\\\\").replace('"', "\\\""), value(c));
            }
        };
        family("elastalert_scrapes", "Number of scrapes for rule", &|c| c.scrapes.to_string());
        family("elastalert_hits", "Number of hits for rule", &|c| c.hits.to_string());
        family("elastalert_matches", "Number of matches for rule", &|c| c.matches.to_string());
        family("elastalert_time_taken", "Time taken to evaluate rule", &|c| c.time_taken.to_string());
        family("elastalert_alerts_sent", "Number of alerts sent for rule", &|c| c.alerts_sent.to_string());
        family("elastalert_alerts_not_sent", "Number of alerts not sent", &|c| c.alerts_not_sent.to_string());
        family("elastalert_alerts_silenced", "Number of silenced alerts", &|c| c.alerts_silenced.to_string());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        let mut gauge = |name: &str, help: &str, value: &dyn Fn(&RuleCounters) -> Option<f64>| {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge");
            for (rule, c) in rules.iter() {
                if let Some(v) = value(c) {
                    let _ = writeln!(out, "{name}{{rule_name=\"{}\"}} {v}", rule.replace('\\', "\\\\").replace('"', "\\\""));
                }
            }
        };
        gauge("elastalert_rule_lag_seconds", "Seconds between now and the end of the last query range of the rule", &|c| c.last_end.map(|e| (now - e).max(0.0)));
        gauge("elastalert_rule_last_success_timestamp_seconds", "Unix time the rule last ran without error", &|c| c.last_success);
        let es = self.es.lock().unwrap();
        let _ = writeln!(out, "# HELP elastalert_es_request_duration_seconds Duration of Elasticsearch requests by kind\n# TYPE elastalert_es_request_duration_seconds histogram");
        for (kind, h) in es.iter() {
            let mut cumulative = 0;
            for (b, n) in BUCKETS.iter().zip(&h.buckets) {
                cumulative += n;
                let _ = writeln!(out, "elastalert_es_request_duration_seconds_bucket{{kind=\"{kind}\",le=\"{b}\"}} {cumulative}");
            }
            let _ = writeln!(out, "elastalert_es_request_duration_seconds_bucket{{kind=\"{kind}\",le=\"+Inf\"}} {}", h.count);
            let _ = writeln!(out, "elastalert_es_request_duration_seconds_sum{{kind=\"{kind}\"}} {}\nelastalert_es_request_duration_seconds_count{{kind=\"{kind}\"}} {}", h.sum, h.count);
        }
        let _ = writeln!(out, "# HELP elastalert_es_request_errors_total Elasticsearch requests that failed, by kind\n# TYPE elastalert_es_request_errors_total counter");
        for (kind, h) in es.iter() {
            let _ = writeln!(out, "elastalert_es_request_errors_total{{kind=\"{kind}\"}} {}", h.errors);
        }
        let _ = writeln!(out, "# HELP elastalert_errors_total Number of errors for rule\n# TYPE elastalert_errors_total counter\nelastalert_errors_total {}", self.errors.load(Ordering::Relaxed));
        out
    }
}

/// Serves `/metrics` (any path) until the process exits.
pub async fn serve(addr: String, metrics: std::sync::Arc<Metrics>) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    log::info!("Prometheus metrics on http://{addr}/metrics");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { continue };
            let m = metrics.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf)).await;
                let body = m.render();
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_kinds() {
        assert_eq!(request_kind("POST", "bench-fat/_search?ignore_unavailable=true"), "search");
        assert_eq!(request_kind("POST", "_search"), "search");
        assert_eq!(request_kind("POST", "_search/scroll"), "scroll");
        assert_eq!(request_kind("POST", "logs-*/_pit?keep_alive=1m"), "pit");
        assert_eq!(request_kind("DELETE", "_pit"), "pit");
        assert_eq!(request_kind("POST", "x/_eql/search"), "eql");
        assert_eq!(request_kind("POST", "_query?format=json"), "esql");
        assert_eq!(request_kind("POST", "x/_count"), "count");
        assert_eq!(request_kind("GET", ""), "get");
    }

    #[test]
    fn histogram_and_lag_are_rendered() {
        let m = Metrics::default();
        m.es_request("search", 0.02, true);
        m.es_request("search", 0.3, true);
        m.es_request("search", 100.0, false);
        m.rule("r", |c| c.last_end = Some(0.0));
        let text = m.render();
        assert!(text.contains("elastalert_es_request_duration_seconds_bucket{kind=\"search\",le=\"0.025\"} 1"), "{text}");
        assert!(text.contains("elastalert_es_request_duration_seconds_bucket{kind=\"search\",le=\"0.5\"} 2"), "{text}");
        assert!(text.contains("elastalert_es_request_duration_seconds_bucket{kind=\"search\",le=\"+Inf\"} 3"), "{text}");
        assert!(text.contains("elastalert_es_request_errors_total{kind=\"search\"} 1"), "{text}");
        assert!(text.contains("elastalert_rule_lag_seconds{rule_name=\"r\"}"), "{text}");
        assert!(!text.contains("elastalert_rule_last_success_timestamp_seconds{"), "no sample before the first run: {text}");
    }
}
