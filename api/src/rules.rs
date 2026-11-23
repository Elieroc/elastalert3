//! Rule files: list, read, write (validated, atomic), enable/disable, dry run.

use crate::{App, auth::Writer, error::{ApiError, Res}, tools};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::{Component, PathBuf}, sync::Arc};
use utoipa::{IntoParams, ToSchema};

type S = State<Arc<App>>;

#[derive(Serialize, ToSchema, Clone)]
pub struct RuleSummary {
    /// Path relative to the rules folder; this is the id used by the other endpoints.
    pub path: String,
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    pub index: Option<String>,
    pub is_enabled: bool,
    pub realert_key: String,
    #[schema(value_type = Vec<Object>)]
    pub mitre_attack: Vec<Value>,
    /// `sigma:` rule (compiled by the daemon at load).
    pub sigma: bool,
    /// Set when the file is not even valid YAML.
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RuleFile {
    pub path: String,
    /// Raw YAML, as on disk.
    pub content: String,
    /// The YAML as JSON; `import:` and `$key$` are not resolved here.
    #[schema(value_type = Object)]
    pub parsed: Value,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RuleFilter {
    /// Rule type, e.g. `frequency`.
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    pub enabled: Option<bool>,
    /// Substring of the name or path.
    pub q: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Saved {
    pub path: String,
    pub created: bool,
}

#[derive(Serialize, ToSchema)]
pub struct Validation {
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Deserialize, ToSchema, Clone)]
pub struct TestRequest {
    /// A rule already on disk (path relative to the rules folder)…
    pub path: Option<String>,
    /// …or an unsaved YAML draft (`path` then only says where its `import:` are resolved from).
    pub content: Option<String>,
    /// ISO8601, e.g. `2026-10-01T08:00:00Z`.
    pub start: Option<String>,
    pub end: Option<String>,
    /// Previous N days (default: the rule's timeframe).
    pub days: Option<u32>,
    pub max_query_size: Option<u64>,
}

/// A relative `.yaml`/`.yml` path inside the rules folder: no `..`, no absolute path, no hidden component.
// ponytail: symlinks inside the rules folder are followed; mount it without untrusted symlinks.
pub fn resolve(root: &std::path::Path, rel: &str) -> Res<PathBuf> {
    let p = std::path::Path::new(rel);
    let ok = !rel.is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(n) if !n.to_string_lossy().starts_with('.')))
        && matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml"));
    if !ok {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "path must be relative, without '..' or hidden parts, and end in .yaml or .yml"));
    }
    Ok(root.join(p))
}

fn summary(rel: String, text: &str) -> RuleSummary {
    let parsed: Result<Value, _> = serde_yaml_ng::from_str(text);
    let (v, error) = match parsed {
        Ok(v @ Value::Object(_)) => (v, None),
        Ok(_) => (json!({}), Some("not a YAML mapping".to_string())),
        Err(e) => (json!({}), Some(e.to_string())),
    };
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let stem = rel.rsplit('/').next().unwrap_or(&rel).rsplit_once('.').map(|x| x.0).unwrap_or(&rel).to_string();
    let name = s("name").unwrap_or(stem);
    RuleSummary {
        realert_key: s("realert_key").unwrap_or_else(|| name.clone()),
        name,
        rule_type: s("type"),
        index: s("index"),
        is_enabled: v.get("is_enabled").and_then(Value::as_bool).unwrap_or(true),
        mitre_attack: v.get("mitre_attack").and_then(Value::as_array).cloned().unwrap_or_default(),
        sigma: v.get("sigma").is_some(),
        path: rel,
        error,
    }
}

/// `(relative path, text)` of every `*.yaml`/`*.yml` under `root` (hidden files and folders skipped), sorted by path.
pub async fn walk(root: &std::path::Path) -> Res<Vec<(String, String)>> {
    let root = root.to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let (path, name) = (e.path(), e.file_name().to_string_lossy().into_owned());
                if name.starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                } else if name.ends_with(".yaml") || name.ends_with(".yml") {
                    let rel = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().into_owned();
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        out.push((rel, text));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    Ok(out)
}

pub async fn scan(app: &App) -> Res<Vec<RuleSummary>> {
    Ok(walk(&app.cfg.rules_dir).await?.into_iter().map(|(rel, text)| summary(rel, &text)).collect())
}

/// Writes `content` next to its target under a hidden `.tmp` name (so `import:` resolve and the daemon's
/// hot-reload ignores it), checks it, then renames it over the target. Returns whether the rule is new.
async fn write_checked(app: &App, rel: &str, content: &str) -> Res<bool> {
    let target = resolve(&app.cfg.rules_dir, rel)?;
    let parsed: Value = serde_yaml_ng::from_str(content).map_err(|e| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid YAML: {e}")))?;
    if !parsed.is_object() {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "a rule must be a YAML mapping"));
    }
    let new = summary(rel.to_string(), content);
    if let Some(other) = scan(app).await?.iter().find(|r| r.name == new.name && r.path != rel) {
        return Err(ApiError::new(StatusCode::CONFLICT, format!("rule name \"{}\" is already used by {}", new.name, other.path)));
    }
    let tmp = tmp_beside(&target);
    if let Some(dir) = target.parent() {
        tokio::fs::create_dir_all(dir).await.map_err(|e| anyhow::anyhow!(e))?;
    }
    tokio::fs::write(&tmp, content).await.map_err(|e| anyhow::anyhow!(e))?;
    let verdict = tools::check(app, &tmp).await;
    match verdict {
        Ok(Ok(())) => {
            let created = !target.exists();
            tokio::fs::rename(&tmp, &target).await.map_err(|e| anyhow::anyhow!(e))?;
            Ok(created)
        }
        other => {
            let _ = tokio::fs::remove_file(&tmp).await;
            match other? {
                Err(msg) => Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, msg.replace(&*tmp.to_string_lossy(), rel))),
                Ok(()) => unreachable!(),
            }
        }
    }
}

pub fn tmp_beside(target: &std::path::Path) -> PathBuf {
    target.with_file_name(format!(".{}.{}.tmp", target.file_name().unwrap_or_default().to_string_lossy(), uuid::Uuid::new_v4().simple()))
}

#[utoipa::path(get, path = "/rules", params(RuleFilter), tag = "rules",
    responses((status = 200, body = Vec<RuleSummary>)))]
pub async fn list(State(app): S, Query(f): Query<RuleFilter>) -> Res<Json<Vec<RuleSummary>>> {
    let q = f.q.map(|q| q.to_lowercase());
    let rules = scan(&app).await?;
    Ok(Json(
        rules
            .into_iter()
            .filter(|r| f.rule_type.as_ref().is_none_or(|t| r.rule_type.as_ref() == Some(t)))
            .filter(|r| f.enabled.is_none_or(|e| r.is_enabled == e))
            .filter(|r| q.as_ref().is_none_or(|q| r.name.to_lowercase().contains(q) || r.path.to_lowercase().contains(q)))
            .collect(),
    ))
}

#[utoipa::path(get, path = "/rules/{path}", tag = "rules",
    params(("path" = String, Path, description = "Rule path, URL-encoded (a%2Fb.yaml)")),
    responses((status = 200, body = RuleFile), (status = 404, description = "No such rule")))]
pub async fn get(State(app): S, Path(rel): Path<String>) -> Res<Json<RuleFile>> {
    let file = resolve(&app.cfg.rules_dir, &rel)?;
    let content = tokio::fs::read_to_string(&file).await.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such rule"))?;
    let parsed = serde_yaml_ng::from_str(&content).unwrap_or(Value::Null);
    Ok(Json(RuleFile { path: rel, content, parsed }))
}

#[utoipa::path(put, path = "/rules/{path}", tag = "rules",
    params(("path" = String, Path, description = "Rule path, URL-encoded")),
    request_body(content = String, content_type = "application/yaml", description = "The rule, as YAML"),
    responses((status = 200, body = Saved, description = "Replaced"), (status = 201, body = Saved, description = "Created"),
        (status = 409, description = "Another file already has this rule name"),
        (status = 422, description = "Invalid YAML or rule rejected by the daemon's loader (message in `error`)")))]
pub async fn put(_: Writer, State(app): S, Path(rel): Path<String>, body: String) -> Res<(StatusCode, Json<Saved>)> {
    let created = write_checked(&app, &rel, &body).await?;
    Ok((if created { StatusCode::CREATED } else { StatusCode::OK }, Json(Saved { path: rel, created })))
}

#[utoipa::path(delete, path = "/rules/{path}", tag = "rules",
    params(("path" = String, Path, description = "Rule path, URL-encoded")),
    responses((status = 204), (status = 404)))]
pub async fn delete(_: Writer, State(app): S, Path(rel): Path<String>) -> Res<StatusCode> {
    let file = resolve(&app.cfg.rules_dir, &rel)?;
    tokio::fs::remove_file(&file).await.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such rule"))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets the top-level `is_enabled` line, adding it if absent. Comments on that line are dropped.
fn with_enabled(src: &str, on: bool) -> String {
    let line = format!("is_enabled: {on}");
    let mut found = false;
    let mut lines: Vec<String> = src
        .lines()
        .map(|l| if l.starts_with("is_enabled:") { found = true; line.clone() } else { l.to_string() })
        .collect();
    if !found {
        lines.push(line);
    }
    lines.join("\n") + "\n"
}

async fn toggle(app: &App, rel: String, on: bool) -> Res<Json<Saved>> {
    let file = resolve(&app.cfg.rules_dir, &rel)?;
    let src = tokio::fs::read_to_string(&file).await.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "no such rule"))?;
    write_checked(app, &rel, &with_enabled(&src, on)).await?;
    Ok(Json(Saved { path: rel, created: false }))
}

#[utoipa::path(post, path = "/rules/{path}/enable", tag = "rules",
    params(("path" = String, Path, description = "Rule path, URL-encoded")), responses((status = 200, body = Saved)))]
pub async fn enable(_: Writer, State(app): S, Path(rel): Path<String>) -> Res<Json<Saved>> {
    toggle(&app, rel, true).await
}

#[utoipa::path(post, path = "/rules/{path}/disable", tag = "rules",
    params(("path" = String, Path, description = "Rule path, URL-encoded")), responses((status = 200, body = Saved)))]
pub async fn disable(_: Writer, State(app): S, Path(rel): Path<String>) -> Res<Json<Saved>> {
    toggle(&app, rel, false).await
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ValidateQuery {
    /// Where the rule would live; its `import:` are resolved from that folder (default: the rules folder).
    pub path: Option<String>,
}

/// A hidden temp file, removed when dropped (also when a cancelled job drops its future).
pub struct Draft(pub PathBuf);

impl Drop for Draft {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[utoipa::path(post, path = "/rules/validate", tag = "rules", params(ValidateQuery),
    request_body(content = String, content_type = "application/yaml"),
    responses((status = 200, body = Validation)))]
pub async fn validate(State(app): S, Query(q): Query<ValidateQuery>, body: String) -> Res<Json<Validation>> {
    let draft = draft_file(&app, q.path.as_deref(), &body).await?;
    Ok(Json(match tools::check(&app, &draft.0).await? {
        Ok(()) => Validation { valid: true, error: None },
        Err(e) => Validation { valid: false, error: Some(e) },
    }))
}

/// A hidden temp copy of `content` in the folder of `rel` (or the rules folder).
async fn draft_file(app: &App, rel: Option<&str>, content: &str) -> Res<Draft> {
    let dir = match rel {
        Some(r) => resolve(&app.cfg.rules_dir, r)?.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| app.cfg.rules_dir.clone()),
        None => app.cfg.rules_dir.clone(),
    };
    let tmp = tmp_beside(&dir.join("draft.yaml"));
    tokio::fs::create_dir_all(&dir).await.map_err(|e| anyhow::anyhow!(e))?;
    tokio::fs::write(&tmp, content).await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(Draft(tmp))
}

/// `elastalert test-rule --formatted-output` on a rule on disk or a draft; shared by the synchronous endpoint and the jobs.
pub async fn run_test(app: &App, t: TestRequest, timeout_secs: u64) -> Res<Value> {
    let (file, _draft) = match (&t.content, &t.path) {
        (Some(c), p) => {
            let d = draft_file(app, p.as_deref(), c).await?;
            (d.0.clone(), Some(d))
        }
        (None, Some(p)) => (resolve(&app.cfg.rules_dir, p)?, None),
        (None, None) => return Err(ApiError::new(StatusCode::BAD_REQUEST, "give `path` or `content`")),
    };
    // `--opt=value` form: a value can never be taken for another flag.
    let mut args = vec!["test-rule".to_string(), file.to_string_lossy().into_owned(), "--formatted-output".into()];
    args.extend(t.start.map(|v| format!("--start={v}")));
    args.extend(t.end.map(|v| format!("--end={v}")));
    args.extend(t.days.map(|v| format!("--days={v}")));
    args.extend(t.max_query_size.map(|v| format!("--max-query-size={v}")));
    let out = tools::run_for(app, &args, timeout_secs).await?;
    if out.code != 0 {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, out.stderr.trim().to_string()));
    }
    let mut v: Value = serde_json::from_str(&out.stdout).unwrap_or_else(|_| json!({"output": out.stdout}));
    // The daemon exits 0 on a failed query (ES down, bad filter) and says so on stderr.
    if let (Some(o), false) = (v.as_object_mut(), out.stderr.trim().is_empty()) {
        o.insert("_log".into(), json!(out.stderr.trim()));
    }
    Ok(v)
}

#[utoipa::path(post, path = "/rules/test", tag = "rules", request_body = TestRequest,
    description = "Synchronous, limited to `API_TEST_TIMEOUT_SECS`. For long ranges use `POST /rules/test/jobs`.",
    responses((status = 200, description = "`elastalert test-rule --formatted-output`: query, results, alerts that would be sent", body = Object),
        (status = 422, description = "Invalid rule"), (status = 504, description = "Test took too long")))]
pub async fn test(State(app): S, Json(t): Json<TestRequest>) -> Res<Json<Value>> {
    Ok(Json(run_test(&app, t, app.cfg.timeout_secs).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let root = std::path::Path::new("/r");
        assert!(resolve(root, "a/b.yaml").is_ok());
        for bad in ["", "/etc/x.yaml", "../x.yaml", "a/../../x.yml", ".hidden.yaml", "a.txt", "a/.b/c.yaml"] {
            assert!(resolve(root, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn enabled_line() {
        assert_eq!(with_enabled("name: a\nis_enabled: true\n", false), "name: a\nis_enabled: false\n");
        assert_eq!(with_enabled("name: a", false), "name: a\nis_enabled: false\n");
    }

    #[test]
    fn summary_defaults() {
        let s = summary("x/my.yaml".into(), "type: frequency\nmitre_attack: [T1059]\n");
        assert_eq!((s.name.as_str(), s.is_enabled, s.realert_key.as_str()), ("my", true, "my"));
        assert!(summary("a.yaml".into(), "a: [").error.is_some());
    }
}
