//! The daemon's own binary does the validation, test runs and conversions, so the API never disagrees with it.

use crate::{App, error::{ApiError, Res}};
use anyhow::Context;
use axum::http::StatusCode;
use std::{path::Path, time::Duration};
use tokio::process::Command;

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// `elastalert --config <config> <args…>` from the daemon's working directory (rules_folder is relative to it).
pub async fn run(app: &App, args: &[String]) -> Res<Out> {
    run_for(app, args, app.cfg.timeout_secs).await
}

pub async fn run_for(app: &App, args: &[String], timeout_secs: u64) -> Res<Out> {
    let child = Command::new(&app.cfg.bin)
        .arg("--config")
        .arg(&app.cfg.config)
        .args(args)
        .current_dir(&app.cfg.workdir)
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(timeout_secs), child)
        .await
        .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, format!("{} timed out after {timeout_secs}s", args.first().map(String::as_str).unwrap_or("command"))))?
        .with_context(|| format!("cannot run {}", app.cfg.bin))?;
    Ok(Out {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Loads one rule file the way the daemon does (imports, defaults, unsupported options). `Ok(Err(msg))` = invalid rule.
pub async fn check(app: &App, file: &Path) -> Res<Result<(), String>> {
    let o = run(app, &["test-rule".into(), file.to_string_lossy().into_owned(), "--schema-only".into()]).await?;
    match o.code {
        0 => Ok(Ok(())),
        3 => Ok(Err(o.stderr.trim().trim_start_matches("Invalid rule file: ").to_string())),
        _ => Err(anyhow::anyhow!("test-rule failed ({}): {}", o.code, o.stderr.trim()).into()),
    }
}
