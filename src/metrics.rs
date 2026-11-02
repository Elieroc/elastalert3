//! Prometheus metrics (`--prometheus_port`): upstream's names for the per-rule counters, plus rule lag and the
//! duration of Elasticsearch requests. Hand-rolled text exposition, no dependency.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

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
    /// CPU time of the rule's runs, see [`Usage`].
    pub cpu_seconds: f64,
    pub allocated_bytes: u64,
    /// Peak memory of the last run, see [`Usage`].
    pub memory_peak: Option<f64>,
}

/// What one rule costs, measured on its own task while a run is polled ([`measure`]): thread CPU time, and the
/// heap allocated and freed meanwhile (through [`Tracking`]). Work done on its behalf by other tasks (TLS and HTTP
/// framing on the shared connections, the writeback task) is not counted.
#[derive(Default)]
pub struct Usage {
    cpu_ns: AtomicU64,
    allocated: AtomicU64,
    /// Bytes allocated minus bytes freed since the last `take`, and its maximum.
    live: AtomicI64,
    peak: AtomicI64,
}

impl Usage {
    /// (CPU seconds, bytes allocated, peak live bytes) since the last call.
    pub fn take(&self) -> (f64, u64, i64) {
        self.live.store(0, Ordering::Relaxed);
        (self.cpu_ns.swap(0, Ordering::Relaxed) as f64 / 1e9, self.allocated.swap(0, Ordering::Relaxed), self.peak.swap(0, Ordering::Relaxed))
    }
}

thread_local! {
    /// The `Usage` of the future being polled on this thread, null outside [`measure`].
    static CURRENT: Cell<*const Usage> = const { Cell::new(std::ptr::null()) };
}

fn thread_cpu_ns() -> u64 {
    #[cfg(unix)]
    {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: valid out pointer; the clock exists on every unix this builds for.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
    #[cfg(not(unix))]
    0
}

/// Runs `fut`, charging the CPU time and allocations of each of its polls to `usage`.
pub async fn measure<F: Future>(usage: &Usage, fut: F) -> F::Output {
    struct Guard<'a>(&'a Usage, *const Usage, u64);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            CURRENT.with(|c| c.set(self.1));
            self.0.cpu_ns.fetch_add(thread_cpu_ns().saturating_sub(self.2), Ordering::Relaxed);
        }
    }
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        let _g = Guard(usage, CURRENT.with(|c| c.replace(usage)), thread_cpu_ns());
        fut.as_mut().poll(cx)
    })
    .await
}

/// The global allocator: mimalloc, plus the accounting of [`measure`].
pub struct Tracking;

fn track(delta: isize) {
    let _ = CURRENT.try_with(|c| {
        // SAFETY: only set while `measure` borrows the `Usage`.
        let Some(u) = (unsafe { c.get().as_ref() }) else { return };
        if delta > 0 {
            u.allocated.fetch_add(delta as u64, Ordering::Relaxed);
        }
        let live = u.live.fetch_add(delta as i64, Ordering::Relaxed) + delta as i64;
        if live > u.peak.load(Ordering::Relaxed) {
            u.peak.store(live, Ordering::Relaxed);
        }
    });
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { mimalloc::MiMalloc.alloc(l) };
        if !p.is_null() {
            track(l.size() as isize);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { mimalloc::MiMalloc.alloc_zeroed(l) };
        if !p.is_null() {
            track(l.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { mimalloc::MiMalloc.dealloc(p, l) };
        track(-(l.size() as isize));
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { mimalloc::MiMalloc.realloc(p, l, new) };
        if !q.is_null() {
            track(new as isize - l.size() as isize);
        }
        q
    }
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
        family("elastalert_rule_cpu_seconds", "CPU time used by the runs of the rule", &|c| c.cpu_seconds.to_string());
        family("elastalert_rule_allocated_bytes", "Heap allocated by the runs of the rule", &|c| c.allocated_bytes.to_string());
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
        gauge("elastalert_rule_memory_peak_bytes", "Peak heap held by the last run of the rule, above what it held before", &|c| c.memory_peak);
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

    #[tokio::test]
    async fn usage_counts_cpu_and_memory_of_the_measured_future_only() {
        let u = Usage::default();
        let outside = vec![0u8; 4 << 20];
        let n = measure(&u, async {
            let big = vec![1u8; 1 << 20];
            tokio::task::yield_now().await;
            let spin = (0..20_000_000u64).fold(0u64, |a, x| a.wrapping_add(std::hint::black_box(x)));
            drop(big);
            spin
        })
        .await;
        drop(outside);
        assert!(n > 0);
        let (cpu, allocated, peak) = u.take();
        assert!(cpu > 0.0, "{cpu}");
        assert!((1 << 20..2 << 20).contains(&allocated), "{allocated}");
        assert!((1 << 20..2 << 20).contains(&peak), "{peak}");
        assert_eq!(u.take(), (0.0, 0, 0));
    }
}
