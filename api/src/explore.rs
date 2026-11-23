//! Helpers for writing rules: the daemon's config (secrets masked) and read-only views of the Elasticsearch indices.

use crate::{App, error::{ApiError, Res}};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

type S = State<Arc<App>>;

const SECRET_KEYS: [&str; 11] = ["password", "passwd", "secret", "token", "api_key", "apikey", "private_key", "bearer", "webhook", "credential", "authorization"];

fn mask(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, v) in m.iter_mut() {
                let k = k.to_lowercase();
                if SECRET_KEYS.iter().any(|s| k.contains(s)) {
                    *v = json!("***");
                } else {
                    mask(v);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(mask),
        _ => {}
    }
}

#[derive(Serialize, ToSchema)]
pub struct ConfigView {
    pub path: String,
    /// `config.yaml` as JSON; values of keys that look like secrets (password, token, api_key, webhook…) are `***`.
    #[schema(value_type = Object)]
    pub config: Value,
}

#[utoipa::path(get, path = "/config", tag = "config", description = "Read-only. A change of config.yaml needs a restart of the daemon, which the API does not do.",
    responses((status = 200, body = ConfigView)))]
pub async fn config(State(app): S) -> Res<Json<ConfigView>> {
    let text = tokio::fs::read_to_string(&app.cfg.config).await.map_err(|e| anyhow::anyhow!("cannot read {}: {e}", app.cfg.config.display()))?;
    let mut config: Value = serde_yaml_ng::from_str(&text).map_err(|e| anyhow::anyhow!("config.yaml is not valid YAML: {e}"))?;
    mask(&mut config);
    Ok(Json(ConfigView { path: app.cfg.config.display().to_string(), config }))
}

/// An index pattern as the Elasticsearch URL takes it: letters, digits, `. _ - * , :`, not starting with `_`.
fn pattern(p: &str) -> Res<&str> {
    let ok = !p.is_empty() && p.len() <= 256 && !p.starts_with('_') && p.chars().all(|c| c.is_ascii_alphanumeric() || ".-_*,:".contains(c));
    if ok { Ok(p) } else { Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid index pattern")) }
}

/// Maps a non-2xx Elasticsearch answer to an error with its reason.
fn es_error(status: StatusCode, body: &Value) -> ApiError {
    let reason = body["error"]["reason"].as_str().or(body["error"].as_str()).unwrap_or("Elasticsearch error");
    let code = if status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST { status } else { StatusCode::BAD_GATEWAY };
    ApiError::new(code, reason)
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct IndicesQuery {
    /// Index pattern (default `*`).
    pub pattern: Option<String>,
}

#[utoipa::path(get, path = "/indices", params(IndicesQuery), tag = "indices",
    description = "Indices matching a pattern (hidden ones excluded): health, document count, size.",
    responses((status = 200, body = Vec<Object>)))]
pub async fn indices(State(app): S, Query(q): Query<IndicesQuery>) -> Res<Json<Value>> {
    let p = q.pattern.unwrap_or_else(|| "*".into());
    let path = format!("_cat/indices/{}?format=json&h=index,health,status,docs.count,store.size&s=index", pattern(&p)?);
    let (status, body) = app.es.raw(Method::GET, &path, None).await?;
    if !status.is_success() {
        return Err(es_error(status, &body));
    }
    Ok(Json(body))
}

#[derive(Serialize, ToSchema)]
pub struct Field {
    pub name: String,
    /// Types across the matching indices (more than one = a mapping conflict).
    pub types: Vec<String>,
    pub searchable: bool,
    pub aggregatable: bool,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FieldsQuery {
    /// Substring of the field name.
    pub q: Option<String>,
    /// Max fields (default 500, max 5000).
    pub limit: Option<usize>,
}

#[utoipa::path(get, path = "/indices/{pattern}/fields", tag = "indices", params(("pattern" = String, Path, description = "Index pattern, e.g. logs-*"), FieldsQuery),
    description = "Fields and types of the matching indices (`_field_caps`).",
    responses((status = 200, body = Vec<Field>), (status = 404, description = "No such index")))]
pub async fn fields(State(app): S, Path(p): Path<String>, Query(q): Query<FieldsQuery>) -> Res<Json<Vec<Field>>> {
    let path = format!("{}/_field_caps?fields=*&ignore_unavailable=true&allow_no_indices=false", pattern(&p)?);
    let (status, body) = app.es.raw(Method::GET, &path, None).await?;
    if !status.is_success() {
        return Err(es_error(status, &body));
    }
    let needle = q.q.map(|n| n.to_lowercase());
    let mut out: Vec<Field> = body["fields"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(n, _)| !n.starts_with('_') && needle.as_ref().is_none_or(|q| n.to_lowercase().contains(q)))
        .map(|(n, types)| {
            let t = types.as_object().cloned().unwrap_or_default();
            Field {
                name: n.clone(),
                types: t.keys().cloned().collect(),
                searchable: t.values().all(|v| v["searchable"].as_bool().unwrap_or(false)),
                aggregatable: t.values().all(|v| v["aggregatable"].as_bool().unwrap_or(false)),
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.truncate(q.limit.unwrap_or(500).min(5000));
    Ok(Json(out))
}

const ALLOWED: [&str; 8] = ["query", "size", "from", "sort", "_source", "fields", "aggs", "aggregations"];

/// A body that only reads: whitelisted top-level keys, no script anywhere, size capped, short timeout.
fn checked_body(body: Value) -> Result<Value, String> {
    fn scripts(v: &Value) -> bool {
        match v {
            Value::Object(m) => m.iter().any(|(k, v)| k.contains("script") || scripts(v)),
            Value::Array(a) => a.iter().any(scripts),
            _ => false,
        }
    }
    let Value::Object(mut m) = body else { return Err("the body must be a JSON object".into()) };
    if let Some(k) = m.keys().find(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(format!("`{k}` is not allowed; use {}", ALLOWED.join(", ")));
    }
    if m.values().any(scripts) {
        return Err("scripts are not allowed".into());
    }
    let size = m.get("size").and_then(Value::as_u64).unwrap_or(10).min(100);
    m.insert("size".into(), json!(size));
    m.insert("timeout".into(), json!("10s"));
    Ok(Value::Object(m))
}

#[utoipa::path(post, path = "/indices/{pattern}/search", tag = "indices", params(("pattern" = String, Path, description = "Index pattern, e.g. logs-*")),
    request_body(content = Object, description = "Query DSL. Only query, size (max 100), from, sort, _source, fields, aggs; no scripts."),
    description = "Read-only search to try a filter before putting it in a rule.",
    responses((status = 200, body = Object), (status = 400, description = "Body refused or query rejected by Elasticsearch")))]
pub async fn search(State(app): S, Path(p): Path<String>, Json(body): Json<Value>) -> Res<Json<Value>> {
    let body = checked_body(body).map_err(|m| ApiError::new(StatusCode::BAD_REQUEST, m))?;
    let path = format!("{}/_search?ignore_unavailable=true&allow_no_indices=false&rest_total_hits_as_int=true", pattern(&p)?);
    let (status, resp) = app.es.raw(Method::POST, &path, Some(&body)).await?;
    if !status.is_success() {
        return Err(es_error(status, &resp));
    }
    Ok(Json(resp))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_secrets_only() {
        let mut v = json!({"es_host": "h", "es_password": "p", "nested": {"api_key": "k", "slack_webhook_url": "u", "realert": {"minutes": 1}}, "l": [{"token": "t"}]});
        mask(&mut v);
        assert_eq!(v, json!({"es_host": "h", "es_password": "***", "nested": {"api_key": "***", "slack_webhook_url": "***", "realert": {"minutes": 1}}, "l": [{"token": "***"}]}));
    }

    #[test]
    fn patterns() {
        for ok in ["logs-*", "a,b", "winlogbeat-*", "cluster:idx"] {
            assert!(pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["", "_all", "a/b", "a?b", "a b", "../x"] {
            assert!(pattern(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn search_body() {
        let b = checked_body(json!({"query": {"match_all": {}}, "size": 5000})).unwrap();
        assert_eq!((b["size"].as_u64(), b["timeout"].as_str()), (Some(100), Some("10s")));
        assert!(checked_body(json!({"query": {"script": {"script": "1"}}})).is_err());
        assert!(checked_body(json!({"runtime_mappings": {}})).is_err());
        assert!(checked_body(json!([1])).is_err());
    }
}
