//! The plain Sigma rule files of `sigma_folders`: the daemon compiles each one into a rule at load.
//! Validation is `elastalert sigma-convert` on the file, with the folder as context for correlations and filters.

use crate::{App, auth::Writer, error::{ApiError, Res}, rules::{self, Saved}, tools};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};
use utoipa::ToSchema;

type S = State<Arc<App>>;

#[derive(Serialize, ToSchema)]
pub struct SigmaSummary {
    pub path: String,
    /// `rule`, `correlation` or `filter` (from the first document of the file).
    pub kind: String,
    pub title: Option<String>,
    pub id: Option<String>,
    pub status: Option<String>,
    pub level: Option<String>,
    pub tags: Vec<String>,
    #[schema(value_type = Object)]
    pub logsource: Value,
    /// A file may hold several YAML documents.
    pub documents: usize,
    pub error: Option<String>,
}

fn documents(text: &str) -> Result<Vec<Value>, String> {
    serde_yaml_ng::Deserializer::from_str(text).map(|d| Value::deserialize(d).map_err(|e| e.to_string())).collect()
}

fn summary(rel: String, text: &str) -> SigmaSummary {
    let (docs, error) = match documents(text) {
        Ok(d) => (d, None),
        Err(e) => (vec![], Some(e)),
    };
    let first = docs.first().cloned().unwrap_or(Value::Null);
    let s = |k: &str| first.get(k).and_then(Value::as_str).map(str::to_string);
    SigmaSummary {
        kind: if first.get("correlation").is_some() { "correlation" } else if first.get("filter").is_some() { "filter" } else { "rule" }.into(),
        title: s("title"),
        id: s("id"),
        status: s("status"),
        level: s("level"),
        tags: first.get("tags").and_then(Value::as_array).map(|t| t.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default(),
        logsource: first.get("logsource").cloned().unwrap_or(Value::Null),
        documents: docs.len(),
        path: rel,
        error,
    }
}

fn dir(app: &App) -> Res<&PathBuf> {
    app.cfg.sigma_dir.as_ref().ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no Sigma folder: `sigma_folders` is not set in config.yaml (or SIGMA_DIR)"))
}

#[utoipa::path(get, path = "/sigma/rules", tag = "sigma", description = "Plain Sigma files of the first `sigma_folders` entry (or `SIGMA_DIR`).",
    responses((status = 200, body = Vec<SigmaSummary>), (status = 404, description = "No Sigma folder configured")))]
pub async fn list(State(app): S) -> Res<Json<Vec<SigmaSummary>>> {
    let root = dir(&app)?;
    Ok(Json(rules::walk(root).await?.into_iter().map(|(rel, text)| summary(rel, &text)).collect()))
}

#[derive(Serialize, ToSchema)]
pub struct SigmaFile {
    pub path: String,
    pub content: String,
}

#[utoipa::path(get, path = "/sigma/rules/{path}", tag = "sigma", params(("path" = String, Path, description = "Path in the Sigma folder, URL-encoded")),
    responses((status = 200, body = SigmaFile), (status = 404)))]
pub async fn get(State(app): S, Path(rel): Path<String>) -> Res<Json<SigmaFile>> {
    let file = rules::resolve(dir(&app)?, &rel)?;
    let content = tokio::fs::read_to_string(&file).await.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such Sigma rule"))?;
    Ok(Json(SigmaFile { path: rel, content }))
}

#[utoipa::path(put, path = "/sigma/rules/{path}", tag = "sigma", params(("path" = String, Path, description = "Path in the Sigma folder, URL-encoded")),
    request_body(content = String, content_type = "application/yaml", description = "A Sigma rule, or a multi-document file"),
    responses((status = 200, body = Saved, description = "Replaced"), (status = 201, body = Saved, description = "Created"), (status = 422, description = "Rejected by `sigma-convert`")))]
pub async fn put(_: Writer, State(app): S, Path(rel): Path<String>, body: String) -> Res<(StatusCode, Json<Saved>)> {
    let root = dir(&app)?;
    let target = rules::resolve(root, &rel)?;
    if let Err(e) = documents(&body) {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid YAML: {e}")));
    }
    if let Some(d) = target.parent() {
        tokio::fs::create_dir_all(d).await.map_err(|e| anyhow::anyhow!(e))?;
    }
    let tmp = rules::Draft(rules::tmp_beside(&target));
    tokio::fs::write(&tmp.0, &body).await.map_err(|e| anyhow::anyhow!(e))?;
    let args = vec!["sigma-convert".to_string(), tmp.0.to_string_lossy().into_owned(), format!("--rules={}", root.display())];
    let out = tools::run(&app, &args).await?;
    if out.code != 0 {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, out.stderr.trim().replace(&*tmp.0.to_string_lossy(), &rel)));
    }
    let created = !target.exists();
    tokio::fs::rename(&tmp.0, &target).await.map_err(|e| anyhow::anyhow!(e))?;
    Ok((if created { StatusCode::CREATED } else { StatusCode::OK }, Json(Saved { path: rel, created })))
}

#[utoipa::path(delete, path = "/sigma/rules/{path}", tag = "sigma", params(("path" = String, Path, description = "Path in the Sigma folder, URL-encoded")),
    responses((status = 204), (status = 404)))]
pub async fn delete(_: Writer, State(app): S, Path(rel): Path<String>) -> Res<StatusCode> {
    let file = rules::resolve(dir(&app)?, &rel)?;
    tokio::fs::remove_file(&file).await.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such Sigma rule"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_of_multi_document_file() {
        let s = summary("a.yml".into(), "title: T\nid: 1\ntags: [attack.t1059]\nlogsource: {product: windows}\n---\ncorrelation: {type: event_count}\n");
        assert_eq!((s.kind.as_str(), s.documents, s.title.as_deref(), s.tags.len()), ("rule", 2, Some("T"), 1));
        assert_eq!(summary("c.yml".into(), "correlation: {type: x}\n").kind, "correlation");
        assert!(summary("b.yml".into(), "a: [").error.is_some());
    }
}
