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
}

/// What one rule costs, measured on its own task while a run is polled ([`measure`]): thread CPU time, and the
/// memory it holds (through [`Tracking`]). Work done on its behalf by other tasks (TLS and HTTP framing on the
/// shared connections, the writeback task) is not counted as CPU.
#[derive(Default)]
pub struct Usage {
    cpu_ns: AtomicU64,
    /// Bytes of the live allocator blocks stamped with this rule, whichever task frees them.
    held: AtomicI64,
}

impl Usage {
    /// CPU seconds since the last call.
    pub fn take_cpu(&self) -> f64 {
        self.cpu_ns.swap(0, Ordering::Relaxed) as f64 / 1e9
    }

    /// Memory held by the rule now, in bytes.
    pub fn held(&self) -> i64 {
        self.held.load(Ordering::Relaxed)
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

/// Runs `fut`, charging its CPU time to `usage` and stamping what it allocates with it. `usage` is `'static`
/// because stamped blocks outlive the run (and the task): see [`Metrics::usage`].
pub async fn measure<F: Future>(usage: &'static Usage, fut: F) -> F::Output {
    struct Guard(&'static Usage, *const Usage, u64);
    impl Drop for Guard {
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

/// The global allocator: mimalloc, plus the memory accounting of [`measure`].
///
/// Every block carries an 8-byte header just before the pointer it hands out, holding the `Usage` that was
/// current when it was allocated (null if none). Freeing reads it back, so memory a rule allocated and another
/// task frees (a document sent to the writeback task) leaves the rule's count, and memory a rule keeps between
/// runs stays in it. A block's size is what mimalloc really reserves for it (`mi_usable_size`, header included).
pub struct Tracking;

const HEADER: usize = std::mem::size_of::<*const Usage>();

/// Bytes in front of the user pointer: the header, rounded up to the alignment so the pointer stays aligned.
fn pad(l: Layout) -> usize {
    l.align().max(HEADER)
}

/// The layout actually requested from mimalloc for the user layout `l` and a user size.
fn outer(l: Layout, size: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(pad(l))?, l.align()).ok()
}

fn current() -> *const Usage {
    CURRENT.try_with(Cell::get).unwrap_or(std::ptr::null())
}

/// Size mimalloc reserves for the block starting at `base`.
fn reserved(base: *mut u8) -> i64 {
    // SAFETY: `base` is a live block from mimalloc.
    unsafe { libmimalloc_sys::mi_usable_size(base as *const _) as i64 }
}

/// Writes the header of the fresh block `base`, charges the current rule and returns the user pointer.
unsafe fn stamp(base: *mut u8, pad: usize) -> *mut u8 {
    let owner = current();
    unsafe {
        let user = base.add(pad);
        (user.sub(HEADER) as *mut *const Usage).write_unaligned(owner);
        if let Some(u) = owner.as_ref() {
            u.held.fetch_add(reserved(base), Ordering::Relaxed);
        }
        user
    }
}

unsafe fn owner_of(user: *mut u8) -> *const Usage {
    unsafe { (user.sub(HEADER) as *const *const Usage).read_unaligned() }
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let Some(o) = outer(l, l.size()) else { return std::ptr::null_mut() };
        let base = unsafe { mimalloc::MiMalloc.alloc(o) };
        if base.is_null() { base } else { unsafe { stamp(base, pad(l)) } }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let Some(o) = outer(l, l.size()) else { return std::ptr::null_mut() };
        let base = unsafe { mimalloc::MiMalloc.alloc_zeroed(o) };
        if base.is_null() { base } else { unsafe { stamp(base, pad(l)) } }
    }
    unsafe fn dealloc(&self, user: *mut u8, l: Layout) {
        let p = pad(l);
        unsafe {
            let base = user.sub(p);
            if let Some(u) = owner_of(user).as_ref() {
                u.held.fetch_sub(reserved(base), Ordering::Relaxed);
            }
            // The layout was valid at `alloc`, so it is now.
            mimalloc::MiMalloc.dealloc(base, outer(l, l.size()).unwrap_unchecked());
        }
    }
    unsafe fn realloc(&self, user: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let p = pad(l);
        let Some(new_outer) = outer(l, new) else { return std::ptr::null_mut() };
        unsafe {
            let base = user.sub(p);
            let owner = owner_of(user);
            let before = if owner.is_null() { 0 } else { reserved(base) };
            let q = mimalloc::MiMalloc.realloc(base, outer(l, l.size()).unwrap_unchecked(), new_outer.size());
            if q.is_null() {
                return q;
            }
            // The header is inside the bytes realloc copies. A block nobody owned is adopted by the rule that
            // grows it (a `Vec` built before the run, filled during it).
            let owner = if owner.is_null() {
                let cur = current();
                (q.add(p - HEADER) as *mut *const Usage).write_unaligned(cur);
                cur
            } else {
                owner
            };
            if let Some(u) = owner.as_ref() {
                u.held.fetch_add(reserved(q) - before, Ordering::Relaxed);
            }
            q.add(p)
        }
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
    usages: Mutex<BTreeMap<String, &'static Usage>>,
    errors: AtomicU64,
    es: Mutex<BTreeMap<&'static str, Histogram>>,
}

impl Metrics {
    pub fn rule(&self, name: &str, f: impl FnOnce(&mut RuleCounters)) {
        f(self.rules.lock().unwrap().entry(name.to_string()).or_default());
    }

    /// The memory accounting of the rule `name`. Leaked on purpose: allocator blocks point at it until they are
    /// freed, which can be after the rule task is gone. One per distinct rule name, kept across reloads.
    pub fn usage(&self, name: &str) -> &'static Usage {
        self.usages.lock().unwrap().entry(name.to_string()).or_insert_with(|| Box::leak(Box::default()))
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
        let _ = writeln!(out, "# HELP elastalert_rule_memory_bytes Memory held by the rule now: what its runs allocated and have not freed, state kept between runs included\n# TYPE elastalert_rule_memory_bytes gauge");
        for (rule, u) in self.usages.lock().unwrap().iter() {
            let _ = writeln!(out, "elastalert_rule_memory_bytes{{rule_name=\"{}\"}} {}", rule.replace('\\', "\\\\").replace('"', "\\\""), u.held().max(0));
        }
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
    async fn usage_counts_cpu_and_held_memory_of_the_measured_future_only() {
        let u: &'static Usage = Box::leak(Box::default());
        let outside = vec![0u8; 4 << 20];
        let (spin, kept) = measure(u, async {
            let kept = vec![1u8; 1 << 20];
            let freed = vec![1u8; 2 << 20];
            tokio::task::yield_now().await;
            drop(freed);
            let spin = (0..20_000_000u64).fold(0u64, |a, x| a.wrapping_add(std::hint::black_box(x)));
            (spin, kept)
        })
        .await;
        assert!(spin > 0);
        assert!(u.take_cpu() > 0.0);
        assert_eq!(u.take_cpu(), 0.0);
        // `kept` outlives the run and is still counted; `outside` never was.
        let held = u.held();
        assert!((1 << 20..(1 << 20) + (128 << 10)).contains(&held), "{held}");
        drop(outside);
        // Freed outside the measured future, on purpose: the header finds the owner.
        drop(kept);
        // What is left is tokio's own bookkeeping, allocated while polling (`yield_now`'s deferred wakers).
        assert!((0..256).contains(&u.held()), "{}", u.held());
    }

    #[tokio::test]
    async fn growing_a_block_allocated_outside_adopts_it_and_alignment_holds() {
        let u: &'static Usage = Box::leak(Box::default());
        let mut v: Vec<u8> = Vec::with_capacity(16);
        let aligned = measure(u, async {
            v.resize(1 << 20, 7);
            #[repr(align(64))]
            struct Wide([u8; 100]);
            let b = Box::new(Wide([0; 100]));
            assert_eq!(&*b as *const Wide as usize % 64, 0);
            drop(b);
            true
        })
        .await;
        assert!(aligned);
        assert!(v.iter().all(|b| *b == 7));
        assert!((1 << 20..(1 << 20) + (128 << 10)).contains(&u.held()), "{}", u.held());
        drop(v);
        assert_eq!(u.held(), 0);
    }

    #[test]
    fn memory_gauge_is_rendered_per_rule() {
        let m = Metrics::default();
        m.usage("r\"x");
        let text = m.render();
        assert!(text.contains("elastalert_rule_memory_bytes{rule_name=\"r\\\"x\"} 0"), "{text}");
        assert!(!text.contains("allocated_bytes") && !text.contains("memory_peak"), "{text}");
    }
}
