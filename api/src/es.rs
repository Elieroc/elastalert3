//! Minimal Elasticsearch/OpenSearch client: only what the API reads and writes.

use anyhow::{Context, Result, bail};
use reqwest::{Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};

pub struct Es {
    c: reqwest::Client,
    url: String,
    auth: Auth,
}

enum Auth {
    None,
    Basic(String, String),
    Header(String),
}

impl Es {
    /// `ES_URL`, then `ES_API_KEY` | `ES_BEARER` | `ES_USERNAME` + `ES_PASSWORD`; `ES_INSECURE=true` skips TLS verification.
    pub fn from_env() -> Result<Es> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let url = env("ES_URL").unwrap_or_else(|| "http://localhost:9200".into()).trim_end_matches('/').to_string();
        let auth = if let Some(k) = env("ES_API_KEY") {
            Auth::Header(format!("ApiKey {k}"))
        } else if let Some(b) = env("ES_BEARER") {
            Auth::Header(format!("Bearer {b}"))
        } else if let Some(u) = env("ES_USERNAME") {
            Auth::Basic(u, env("ES_PASSWORD").unwrap_or_default())
        } else {
            Auth::None
        };
        let c = reqwest::Client::builder()
            .danger_accept_invalid_certs(env("ES_INSECURE").as_deref() == Some("true"))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Es { c, url, auth })
    }

    fn req(&self, m: Method, path: &str) -> RequestBuilder {
        let r = self.c.request(m, format!("{}/{}", self.url, path));
        match &self.auth {
            Auth::None => r,
            Auth::Basic(u, p) => r.basic_auth(u, Some(p)),
            Auth::Header(h) => r.header("Authorization", h),
        }
    }

    pub async fn up(&self) -> bool {
        self.req(Method::GET, "").send().await.is_ok_and(|r| r.status().is_success())
    }

    pub async fn exists(&self, index: &str) -> bool {
        self.req(Method::HEAD, index).send().await.is_ok_and(|r| r.status().is_success())
    }

    /// `{total, items}`; items are the `_source` with the `_id` added. A missing index is an empty result.
    pub async fn search(&self, index: &str, body: Value) -> Result<Value> {
        let mut body = body;
        body["track_total_hits"] = json!(true);
        let r = self.req(Method::POST, &format!("{index}/_search")).json(&body).send().await?;
        if r.status() == StatusCode::NOT_FOUND {
            return Ok(json!({"total": 0, "items": []}));
        }
        let v = ok_json(r).await?;
        let items: Vec<Value> = v["hits"]["hits"]
            .as_array()
            .map(|h| h.iter().map(|h| with_id(h)).collect())
            .unwrap_or_default();
        Ok(json!({"total": v["hits"]["total"]["value"].as_u64().unwrap_or(0), "items": items}))
    }

    pub async fn get_doc(&self, index: &str, id: &str) -> Result<Option<Value>> {
        let r = self.req(Method::GET, &format!("{index}/_doc/{id}")).send().await?;
        if r.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(with_id(&ok_json(r).await?)))
    }

    /// Any request; the status and the JSON body (`Null` if none) are returned whatever the status, the caller decides.
    pub async fn raw(&self, m: Method, path: &str, body: Option<&Value>) -> Result<(StatusCode, Value)> {
        let mut r = self.req(m, path);
        if let Some(b) = body {
            r = r.json(b);
        }
        let r = r.send().await?;
        let status = r.status();
        let text = r.text().await.context("reading Elasticsearch response")?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// Indexes a document and refreshes, so that it is visible right away.
    pub async fn index(&self, index: &str, doc: &Value) -> Result<Value> {
        let r = self.req(Method::POST, &format!("{index}/_doc?refresh=true")).json(doc).send().await?;
        ok_json(r).await
    }
}

fn with_id(hit: &Value) -> Value {
    let mut src = hit["_source"].clone();
    if let Some(o) = src.as_object_mut() {
        o.insert("_id".into(), hit["_id"].clone());
    }
    src
}

async fn ok_json(r: reqwest::Response) -> Result<Value> {
    let status = r.status();
    let text = r.text().await.context("reading Elasticsearch response")?;
    if !status.is_success() {
        bail!("Elasticsearch answered {status}: {}", text.chars().take(500).collect::<String>());
    }
    serde_json::from_str(&text).context("Elasticsearch response is not JSON")
}
