//! Minimal Elasticsearch / OpenSearch REST client: only the endpoints the daemon uses.
//! `es_hosts` gives failover: on a connection error the next host is tried.

use anyhow::{Context, Result, bail};
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// What the cluster is, read once from `GET /`.
pub struct Caps {
    pub major: u32,
    pub minor: u32,
    pub opensearch: bool,
}

/// `--es_debug` (log every request) and `--es_debug_trace` (curl commands in a file).
#[derive(Default)]
pub struct Tracing {
    log: bool,
    file: Option<std::sync::Mutex<std::fs::File>>,
}

#[derive(Clone)]
pub struct Es {
    tracing: Arc<Tracing>,
    metrics: Option<Arc<crate::metrics::Metrics>>,
    caps: Arc<tokio::sync::OnceCell<Caps>>,
    http: reqwest::Client,
    bases: Arc<Vec<String>>,
    current: Arc<AtomicUsize>,
}

fn conf_str<'a>(c: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    c.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

pub fn conf_bool(c: &Map<String, Value>, k: &str) -> Option<bool> {
    match c.get(k)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")),
        _ => None,
    }
}

/// Truncate gigantic ES error bodies the way upstream does (1024 chars).
fn clip(s: &str) -> String {
    match s.char_indices().nth(1024) {
        Some((i, _)) => format!("{}... ({} characters removed)", &s[..i], s.len() - i),
        None => s.to_string(),
    }
}

/// `host`, `host:port` or `scheme://host:port` -> `host:port`.
fn host_port(entry: &str, default_port: &str) -> String {
    let h = entry.split("://").last().unwrap_or(entry).trim_end_matches('/');
    if h.rsplit_once(':').is_some_and(|(_, p)| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty()) {
        h.to_string()
    } else {
        format!("{h}:{default_port}")
    }
}

impl Es {
    /// Builds a client from config.yaml / rule keys (`es_host`/`es_hosts`, `es_port`, `use_ssl`, auth, TLS files).
    pub fn from_conf(c: &Map<String, Value>) -> Result<Es> {
        let port = match c.get("es_port") {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            _ => "9200".into(),
        };
        let mut hosts: Vec<String> = match c.get("es_hosts") {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(|h| host_port(h, &port)).collect(),
            Some(Value::String(s)) => s.split(',').filter(|h| !h.trim().is_empty()).map(|h| host_port(h.trim(), &port)).collect(),
            _ => vec![],
        };
        if hosts.is_empty() {
            hosts.push(host_port(conf_str(c, "es_host").context("es_host missing")?, &port));
        }
        let scheme = if conf_bool(c, "use_ssl").unwrap_or(false) { "https" } else { "http" };
        let prefix = conf_str(c, "es_url_prefix").map(|p| format!("/{}", p.trim_matches('/'))).unwrap_or_default();
        let bases = hosts.iter().map(|h| format!("{scheme}://{h}{prefix}")).collect();

        let mut headers = HeaderMap::new();
        let auth = if let Some(k) = conf_str(c, "es_api_key") {
            Some(format!("ApiKey {k}"))
        } else if let Some(t) = conf_str(c, "es_bearer") {
            Some(format!("Bearer {t}"))
        } else {
            conf_str(c, "es_username").map(|u| {
                let p = conf_str(c, "es_password").unwrap_or("");
                format!("Basic {}", base64(format!("{u}:{p}").as_bytes()))
            })
        };
        if let Some(a) = auth {
            let mut v = HeaderValue::from_str(&a).context("invalid auth header")?;
            v.set_sensitive(true);
            headers.insert(AUTHORIZATION, v);
        }

        let timeout = c.get("es_conn_timeout").and_then(Value::as_u64).unwrap_or(20);
        let mut b = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(timeout.max(1) * 3))
            .connect_timeout(Duration::from_secs(timeout.max(1)))
            .pool_max_idle_per_host(32);
        if conf_bool(c, "verify_certs") == Some(false) {
            b = b.danger_accept_invalid_certs(true);
        }
        if let Some(ca) = conf_str(c, "ca_certs") {
            let pem = std::fs::read(ca).with_context(|| format!("reading ca_certs {ca}"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                b = b.add_root_certificate(cert);
            }
        }
        if let Some(cert) = conf_str(c, "client_cert") {
            let mut pem = std::fs::read(cert).with_context(|| format!("reading client_cert {cert}"))?;
            if let Some(key) = conf_str(c, "client_key") {
                pem.extend(std::fs::read(key).with_context(|| format!("reading client_key {key}"))?);
            }
            b = b.identity(reqwest::Identity::from_pem(&pem)?);
        }
        Ok(Es { tracing: Arc::default(), metrics: None, caps: Arc::new(tokio::sync::OnceCell::new()), http: b.build()?, bases: Arc::new(bases), current: Arc::new(AtomicUsize::new(0)) })
    }

    /// Turns on request logging (`log`) and/or a curl-style trace file (appended to).
    pub fn with_tracing(mut self, log: bool, trace_file: Option<&std::path::Path>) -> Result<Es> {
        let file = trace_file
            .map(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).with_context(|| format!("opening es_debug_trace file {}", p.display())).map(std::sync::Mutex::new))
            .transpose()?;
        self.tracing = Arc::new(Tracing { log, file });
        Ok(self)
    }

    /// Records the duration of every request in the Prometheus metrics.
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Es {
        self.metrics = Some(metrics);
        self
    }

    fn trace(&self, method: &Method, url: &str, body: &Body<'_>, status: Option<u16>, secs: f64, response: &str) {
        if self.tracing.log {
            match status {
                Some(s) => log::info!(target: "elasticsearch", "{method} {url} [status:{s} request:{secs:.3}s]"),
                None => log::info!(target: "elasticsearch", "{method} {url} [failed request:{secs:.3}s]"),
            }
        }
        if let Some(f) = &self.tracing.file {
            use std::io::Write;
            let data = match body {
                Body::None => String::new(),
                Body::Json(v) => format!(" -d '{}'", v.to_string().replace('\'', "'\\''")),
                Body::Ndjson(s) => format!(" --data-binary '{}'", s.replace('\'', "'\\''")),
            };
            let ctype = if matches!(body, Body::Ndjson(_)) { "application/x-ndjson" } else { "application/json" };
            let shown: String = response.chars().take(4096).collect();
            let more = if response.chars().count() > 4096 { " ...(truncated)" } else { "" };
            let _ = writeln!(
                f.lock().unwrap(),
                "curl -H 'Content-Type: {ctype}' -X{method} '{url}'{data}\n#[{}] ({secs:.3}s)\n#{shown}{more}\n",
                status.map_or("failed".to_string(), |s| s.to_string())
            );
        }
    }

    /// Sends a request, trying every host once on connection-level failures.
    async fn request(&self, method: Method, path: &str, body: Body<'_>) -> Result<Value> {
        let n = self.bases.len();
        let first = self.current.load(Ordering::Relaxed);
        let mut last_err = None;
        for i in 0..n {
            let idx = (first + i) % n;
            let url = format!("{}/{}", self.bases[idx], path.trim_start_matches('/'));
            let mut req = self.http.request(method.clone(), url);
            req = match &body {
                Body::None => req,
                Body::Json(v) => req.json(v),
                Body::Ndjson(s) => req.header(CONTENT_TYPE, "application/x-ndjson").body((*s).to_string()),
            };
            let started = std::time::Instant::now();
            let traced = self.tracing.log || self.tracing.file.is_some();
            let sent = req.send().await;
            let kind = crate::metrics::request_kind(method.as_str(), path);
            if traced && let Err(e) = &sent {
                self.trace(&method, &format!("{}/{}", self.bases[idx], path.trim_start_matches('/')), &body, None, started.elapsed().as_secs_f64(), &e.to_string());
            }
            match sent {
                Ok(resp) => {
                    self.current.store(idx, Ordering::Relaxed);
                    let status = resp.status();
                    let text = resp.text().await?;
                    if let Some(m) = &self.metrics {
                        m.es_request(kind, started.elapsed().as_secs_f64(), status.is_success());
                    }
                    if traced {
                        self.trace(&method, &format!("{}/{}", self.bases[idx], path.trim_start_matches('/')), &body, Some(status.as_u16()), started.elapsed().as_secs_f64(), &text);
                    }
                    if !status.is_success() {
                        bail!("HTTP {status}: {}", clip(&text));
                    }
                    return Ok(serde_json::from_str(&text).unwrap_or(Value::Null));
                }
                Err(e) => {
                    if let Some(m) = &self.metrics {
                        m.es_request(kind, started.elapsed().as_secs_f64(), false);
                    }
                    if e.is_connect() || e.is_timeout() {
                        last_err = Some(e);
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
        Err(last_err.map(Into::into).unwrap_or_else(|| anyhow::anyhow!("no Elasticsearch host configured")))
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, Body::None).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.request(Method::POST, path, Body::Json(body)).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.request(Method::PUT, path, Body::Json(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.request(Method::DELETE, path, Body::None).await
    }

    pub async fn exists(&self, index: &str) -> Result<bool> {
        match self.request(Method::HEAD, index, Body::None).await {
            Ok(_) => Ok(true),
            Err(e) if e.to_string().starts_with("HTTP 404") => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn caps(&self) -> Result<&Caps> {
        self.caps
            .get_or_try_init(|| async {
                let info = self.get("").await?;
                let v: Vec<u32> = info["version"]["number"].as_str().context("cannot read ES version")?.split('.').map_while(|p| p.parse().ok()).collect();
                Ok(Caps { major: v.first().copied().unwrap_or(0), minor: v.get(1).copied().unwrap_or(0), opensearch: info["version"]["distribution"] == json!("opensearch") })
            })
            .await
    }

    /// Point in time + `_shard_doc` tiebreaker need Elasticsearch 7.12+.
    pub async fn supports_pit(&self) -> bool {
        self.caps().await.is_ok_and(|c| !c.opensearch && (c.major > 7 || (c.major == 7 && c.minor >= 12)))
    }

    /// `params`: extra URL parameters (`&preference=x`), empty for none.
    pub async fn pit_open(&self, index: &str, keepalive: &str, params: &str) -> Result<String> {
        let r = self.request(Method::POST, &format!("{index}/_pit?keep_alive={keepalive}&ignore_unavailable=true{params}"), Body::None).await?;
        r["id"].as_str().map(String::from).context("no PIT id in response")
    }

    pub async fn pit_search(&self, body: &Value) -> Result<Value> {
        self.post("_search", body).await
    }

    pub async fn pit_close(&self, id: &str) {
        let _ = self.request(Method::DELETE, "_pit", Body::Json(&json!({"id": id}))).await;
    }

    pub async fn count(&self, index: &str, body: &Value) -> Result<u64> {
        let r = self.post(&format!("{index}/_count?ignore_unavailable=true"), body).await?;
        r["count"].as_u64().context("no count in response")
    }

    /// First page of a search, opening a scroll context.
    pub async fn search_scroll(&self, index: &str, body: &Value, size: u64, keepalive: &str, params: &str) -> Result<Value> {
        let path = format!("{index}/_search?scroll={keepalive}&size={size}&ignore_unavailable=true&rest_total_hits_as_int=true{params}");
        self.post(&path, body).await
    }

    pub async fn scroll(&self, id: &str, keepalive: &str) -> Result<Value> {
        self.post("_search/scroll", &json!({"scroll": keepalive, "scroll_id": id})).await
    }

    pub async fn clear_scroll(&self, id: &str) {
        let _ = self.request(Method::DELETE, "_search/scroll", Body::Json(&json!({"scroll_id": id}))).await;
    }

    pub async fn search(&self, index: &str, body: &Value) -> Result<Value> {
        self.search_with(index, body, "").await
    }

    pub async fn search_with(&self, index: &str, body: &Value, params: &str) -> Result<Value> {
        self.post(&format!("{index}/_search?ignore_unavailable=true&rest_total_hits_as_int=true{params}"), body).await
    }

    /// `POST <index>/_eql/search`; the body is the EQL request (`query`, `filter`, `size`).
    pub async fn eql_search(&self, index: &str, body: &Value) -> Result<Value> {
        self.post(&format!("{index}/_eql/search?ignore_unavailable=true"), body).await
    }

    /// `POST _query?format=json`: an ES|QL query (`query`, `filter`).
    pub async fn esql_query(&self, body: &Value) -> Result<Value> {
        self.post("_query?format=json", body).await
    }

    /// Every hit of a query (scrolling), for startup scans.
    pub async fn scan(&self, index: &str, body: &Value, keepalive: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut resp = self.search_scroll(index, body, 1000, keepalive, "").await?;
        loop {
            let hits = resp["hits"]["hits"].as_array().cloned().unwrap_or_default();
            if hits.is_empty() {
                break;
            }
            out.extend(hits);
            let Some(id) = resp["_scroll_id"].as_str().map(String::from) else { break };
            resp = self.scroll(&id, keepalive).await?;
        }
        if let Some(id) = resp["_scroll_id"].as_str() {
            self.clear_scroll(id).await;
        }
        Ok(out)
    }

    /// `_mget` of full `_source` for (index, id) pairs. Missing docs are absent from the result.
    pub async fn mget(&self, docs: &[(String, String)]) -> Result<Vec<Value>> {
        let body = json!({"docs": docs.iter().map(|(i, d)| json!({"_index": i, "_id": d})).collect::<Vec<_>>()});
        let resp = self.post("_mget", &body).await?;
        Ok(resp["docs"].as_array().cloned().unwrap_or_default().into_iter().filter(|d| d["found"] == json!(true)).collect())
    }

    /// `_bulk` with an NDJSON body. Returns the parsed response.
    pub async fn bulk(&self, ndjson: String) -> Result<Value> {
        self.request(Method::POST, "_bulk", Body::Ndjson(&ndjson)).await
    }
}

enum Body<'a> {
    None,
    Json(&'a Value),
    Ndjson(&'a str),
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_basic_auth() {
        assert_eq!(super::base64(b"elastic:changeme"), "ZWxhc3RpYzpjaGFuZ2VtZQ==");
        assert_eq!(super::base64(b"a"), "YQ==");
        assert_eq!(super::base64(b"ab"), "YWI=");
    }

    #[test]
    fn host_forms() {
        assert_eq!(super::host_port("es1", "9200"), "es1:9200");
        assert_eq!(super::host_port("es1:9201", "9200"), "es1:9201");
        assert_eq!(super::host_port("https://es1:9243/", "9200"), "es1:9243");
    }
}
