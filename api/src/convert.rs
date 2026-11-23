//! Sigma conversion and the ATT&CK Navigator layer, both done by the daemon's binary.

use crate::{App, error::{ApiError, Res}, tools};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SigmaQuery {
    /// Return only the search body `{"query": …}` instead of the ElastAlert options.
    pub dsl: Option<bool>,
    /// Built-in pipeline name (field mapping), e.g. `ecs_windows`.
    pub pipeline: Option<String>,
}

#[utoipa::path(post, path = "/sigma/convert", tag = "sigma", params(SigmaQuery),
    request_body(content = String, content_type = "application/yaml", description = "A Sigma rule"),
    responses((status = 200, description = "`{\"yaml\": …}` (ElastAlert options), or the query body with `dsl=true`", body = Object),
        (status = 422, description = "Sigma rule rejected")))]
pub async fn sigma(State(app): State<Arc<App>>, Query(q): Query<SigmaQuery>, body: String) -> Res<Json<Value>> {
    let file = std::env::temp_dir().join(format!("sigma-{}.yml", uuid::Uuid::new_v4().simple()));
    tokio::fs::write(&file, body).await.map_err(|e| anyhow::anyhow!(e))?;
    let mut args = vec!["sigma-convert".to_string(), file.to_string_lossy().into_owned()];
    args.extend(q.pipeline.map(|p| format!("--pipeline={p}")));
    if q.dsl == Some(true) {
        args.push("--dsl".into());
    }
    let out = tools::run(&app, &args).await;
    let _ = tokio::fs::remove_file(&file).await;
    let out = out?;
    if out.code != 0 {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, out.stderr.trim().to_string()));
    }
    Ok(Json(match q.dsl {
        Some(true) => serde_json::from_str(&out.stdout).unwrap_or_else(|_| json!({"output": out.stdout})),
        _ => json!({"yaml": out.stdout}),
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LayerQuery {
    pub name: Option<String>,
    /// Count the rules with `is_enabled: false` too.
    pub include_disabled: Option<bool>,
}

#[utoipa::path(get, path = "/mitre/layer", tag = "sigma", params(LayerQuery),
    description = "ATT&CK Navigator layer of the techniques the deployed rules cover (`mitre_attack`).",
    responses((status = 200, body = Object)))]
pub async fn mitre(State(app): State<Arc<App>>, Query(q): Query<LayerQuery>) -> Res<Json<Value>> {
    let mut args = vec!["mitre-layer".to_string()];
    args.extend(q.name.map(|n| format!("--name={n}")));
    if q.include_disabled == Some(true) {
        args.push("--include-disabled".into());
    }
    let out = tools::run(&app, &args).await?;
    if out.code != 0 {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, out.stderr.trim().to_string()));
    }
    Ok(Json(serde_json::from_str(&out.stdout).map_err(|e| anyhow::anyhow!("layer is not JSON: {e}"))?))
}
