//! The options of each rule type, from the daemon's own catalogue (`elastalert rule-types`).

use crate::{App, error::{ApiError, Res}, tools};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde_json::Value;
use std::sync::Arc;

async fn catalogue(app: &App, name: Option<&str>) -> Res<Value> {
    let args: Vec<String> = ["rule-types"].into_iter().chain(name).map(String::from).collect();
    let out = tools::run(app, &args).await?;
    if out.code != 0 {
        let msg = out.stderr.trim().trim_start_matches("Error: ").to_string();
        let code = if msg.starts_with("unknown rule type") { StatusCode::NOT_FOUND } else { StatusCode::BAD_GATEWAY };
        return Err(ApiError::new(code, msg));
    }
    serde_json::from_str(&out.stdout).map_err(|e| anyhow::anyhow!("rule-types printed invalid JSON: {e}").into())
}

#[utoipa::path(get, path = "/rule-types", tag = "rule-types", operation_id = "list_rule_types",
    responses((status = 200, description = "`[{type, summary}]`, one per rule type the daemon loads", body = Vec<Object>)))]
pub async fn list(State(app): State<Arc<App>>) -> Res<Json<Value>> {
    Ok(Json(catalogue(&app, None).await?))
}

#[utoipa::path(get, path = "/rule-types/{type}", tag = "rule-types", operation_id = "get_rule_type", params(("type" = String, Path, description = "Rule type, e.g. `spike_aggregation`")),
    description = "The options specific to the type. The options every rule has (`index`, `filter`, `alert`, `realert`…) are not listed: see the documentation.\n\n\
        `required` always needed; `one_of` groups of which at least one is needed; a `required` field with `required_if` is needed only in that case.",
    responses((status = 200, description = "`{type, summary, query, required, one_of, optional, doc}`; a field is `{name, type, description, enum?, default?, required_if?}`", body = Object),
        (status = 404, description = "Unknown rule type; the message lists the valid ones")))]
pub async fn get(State(app): State<Arc<App>>, Path(t): Path<String>) -> Res<Json<Value>> {
    // The name goes to the daemon's command line: only what a rule type name is made of.
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        return Err(ApiError::new(StatusCode::NOT_FOUND, format!("unknown rule type {t:?}")));
    }
    Ok(Json(catalogue(&app, Some(&t)).await?))
}
