//! elastalert3 REST API. Separate process and container: it edits the rules folder the daemon hot-reloads,
//! reads/writes the writeback indices, and calls the daemon's binary for validation, test runs and conversions.

mod auth;
mod convert;
mod error;
mod es;
mod explore;
mod history;
mod jobs;
mod rules;
mod sigma_rules;
mod stats;
mod tools;

use axum::{
    Json, Router, middleware,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use utoipa::{Modify, OpenApi, openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme}};
use utoipa_swagger_ui::SwaggerUi;

pub struct Cfg {
    pub rules_dir: PathBuf,
    pub config: PathBuf,
    pub workdir: PathBuf,
    pub bin: String,
    pub wb: String,
    pub read_token: String,
    pub write_token: String,
    pub timeout_secs: u64,
    pub job_timeout_secs: u64,
    pub metrics_url: Option<String>,
    pub sigma_dir: Option<PathBuf>,
}

pub struct App {
    pub cfg: Cfg,
    pub es: es::Es,
    pub http: reqwest::Client,
    pub jobs: std::sync::Mutex<std::collections::HashMap<String, jobs::Job>>,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn load_cfg() -> anyhow::Result<Cfg> {
    let config = PathBuf::from(env("ELASTALERT_CONFIG").unwrap_or_else(|| "/opt/elastalert/config.yaml".into()));
    let workdir = env("ELASTALERT_WORKDIR").map(PathBuf::from).or_else(|| config.parent().map(PathBuf::from)).unwrap_or_else(|| ".".into());
    let conf: Value = std::fs::read_to_string(&config).ok().and_then(|t| serde_yaml_ng::from_str(&t).ok()).unwrap_or(Value::Null);
    let from_config = conf["writeback_index"].as_str().map(str::to_string);
    // The first `sigma_folders` entry (a folder or a list), relative to the daemon's working directory.
    let sigma_dir = env("SIGMA_DIR").map(PathBuf::from).or_else(|| {
        let first = match &conf["sigma_folders"] {
            Value::String(s) => Some(s.clone()),
            Value::Array(a) => a.first().and_then(|v| v.as_str().map(str::to_string)),
            _ => None,
        }?;
        Some(workdir.join(first))
    });
    let token = |k: &str| -> anyhow::Result<String> {
        let t = env(k).ok_or_else(|| anyhow::anyhow!("{k} is required"))?;
        anyhow::ensure!(t.len() >= 16, "{k} must be at least 16 characters");
        Ok(t)
    };
    let (read_token, write_token) = (token("API_READ_TOKEN")?, token("API_WRITE_TOKEN")?);
    anyhow::ensure!(read_token != write_token, "API_READ_TOKEN and API_WRITE_TOKEN must differ");
    Ok(Cfg {
        rules_dir: env("RULES_DIR").map(PathBuf::from).unwrap_or_else(|| workdir.join("rules")),
        config,
        workdir,
        bin: env("ELASTALERT_BIN").unwrap_or_else(|| "elastalert".into()),
        wb: env("WRITEBACK_INDEX").or(from_config).unwrap_or_else(|| "elastalert_status".into()),
        read_token,
        write_token,
        timeout_secs: env("API_TEST_TIMEOUT_SECS").and_then(|v| v.parse().ok()).unwrap_or(120),
        job_timeout_secs: env("API_JOB_TIMEOUT_SECS").and_then(|v| v.parse().ok()).unwrap_or(900),
        metrics_url: env("ELASTALERT_METRICS_URL"),
        sigma_dir,
    })
}

#[utoipa::path(get, path = "/health", tag = "health", security(()),
    description = "No token needed. 503 when Elasticsearch, the writeback index or the rules folder is unreachable.",
    responses((status = 200, body = Object), (status = 503, body = Object)))]
async fn health(State(app): State<Arc<App>>) -> (StatusCode, Json<Value>) {
    let es = app.es.up().await;
    let index = es && app.es.exists(&app.cfg.wb).await;
    let rules_dir = app.cfg.rules_dir.is_dir();
    let daemon = tools::run(&app, &["--version".into()]).await.ok().filter(|o| o.code == 0).map(|o| o.stdout.trim().to_string());
    let ok = es && index && rules_dir;
    (
        if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
        Json(json!({"status": if ok { "ok" } else { "degraded" }, "api": env!("CARGO_PKG_VERSION"), "elastalert": daemon,
            "elasticsearch": es, "writeback_index": index, "rules_dir": rules_dir})),
    )
}

struct Bearer;

impl Modify for Bearer {
    fn modify(&self, o: &mut utoipa::openapi::OpenApi) {
        o.components.get_or_insert_default().add_security_scheme(
            "bearer",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).description(Some("Read token (GET, validate, test, convert) or write token (everything)")).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "elastalert3 API", description = "Manage rules, read alerts and silence rules of an elastalert3 daemon.\n\nTwo bearer tokens: **read** (GET, `/rules/validate`, `/rules/test`, `/sigma/convert`) and **write** (adds PUT/DELETE/POST that change something). Writes are logged as JSON audit lines on stdout."),
    paths(health, stats::status, stats::rules_stats, stats::rule_stats, explore::config, explore::indices, explore::fields, explore::search,
        jobs::start, jobs::list, jobs::get, jobs::cancel, sigma_rules::list, sigma_rules::get, sigma_rules::put, sigma_rules::delete,
        history::lift, rules::list, rules::get, rules::put, rules::delete, rules::enable, rules::disable, rules::validate, rules::test,
        history::alerts, history::pending, history::alert, history::runs, history::errors, history::silences, history::silence,
        convert::sigma, convert::mitre),
    components(schemas(rules::RuleSummary, rules::RuleFile, rules::Saved, rules::Validation, history::Page, history::NewSilence, rules::TestRequest, stats::RuleStats, stats::RuleDetail, stats::Status, explore::ConfigView, explore::Field,
        jobs::JobView, jobs::JobStatus, sigma_rules::SigmaSummary, sigma_rules::SigmaFile)),
    modifiers(&Bearer),
    security(("bearer" = []))
)]
struct Doc;

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/rules", get(rules::list))
        .route("/rules/validate", post(rules::validate))
        .route("/rules/test", post(rules::test))
        .route("/rules/test/jobs", post(jobs::start))
        .route("/rules/stats", get(stats::rules_stats))
        .route("/rules/{path}/stats", get(stats::rule_stats))
        .route("/jobs", get(jobs::list))
        .route("/jobs/{id}", get(jobs::get).delete(jobs::cancel))
        .route("/status", get(stats::status))
        .route("/config", get(explore::config))
        .route("/indices", get(explore::indices))
        .route("/indices/{pattern}/fields", get(explore::fields))
        .route("/indices/{pattern}/search", post(explore::search))
        .route("/sigma/rules", get(sigma_rules::list))
        .route("/sigma/rules/{path}", get(sigma_rules::get).put(sigma_rules::put).delete(sigma_rules::delete))
        .route("/rules/{path}", get(rules::get).put(rules::put).delete(rules::delete))
        .route("/rules/{path}/enable", post(rules::enable))
        .route("/rules/{path}/disable", post(rules::disable))
        .route("/alerts", get(history::alerts))
        .route("/alerts/pending", get(history::pending))
        .route("/alerts/{id}", get(history::alert))
        .route("/runs", get(history::runs))
        .route("/errors", get(history::errors))
        .route("/silences", get(history::silences).post(history::silence))
        .route("/silences/{id}", axum::routing::delete(history::lift))
        .route("/sigma/convert", post(convert::sigma))
        .route("/mitre/layer", get(convert::mitre))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", Doc::openapi()))
        .layer(middleware::from_fn_with_state(app.clone(), auth::layer))
        .with_state(app)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = load_cfg()?;
    let listen = env("API_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".into());
    eprintln!("elastalert-api: rules {} · writeback index {} · listening on http://{listen}/swagger-ui/", cfg.rules_dir.display(), cfg.wb);
    let app = Arc::new(App { cfg, es: es::Es::from_env()?, http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?, jobs: Default::default() });
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, router(app).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
