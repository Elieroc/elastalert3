//! Rule tests that outlive an HTTP request: start, poll, cancel. Kept in memory (lost on restart).

use crate::{App, error::{ApiError, Res}, rules::{self, TestRequest}};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use serde_json::Value;
use std::{sync::Arc, time::{Duration, Instant}};
use tokio::task::AbortHandle;
use utoipa::ToSchema;

const MAX_RUNNING: usize = 4;
const KEEP: usize = 100;
const TTL: Duration = Duration::from_secs(3600);

#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Running,
    Done,
    Failed,
    Cancelled,
}

pub struct Job {
    status: JobStatus,
    path: Option<String>,
    started: String,
    finished: Option<String>,
    finished_at: Option<Instant>,
    result: Option<Value>,
    error: Option<String>,
    abort: Option<AbortHandle>,
}

#[derive(Serialize, ToSchema)]
pub struct JobView {
    pub id: String,
    pub status: JobStatus,
    /// The rule tested (`path` of the request), if it was a file.
    pub path: Option<String>,
    pub started: String,
    pub finished: Option<String>,
    pub error: Option<String>,
    /// The `test-rule` output, once `done` (only in `GET /jobs/{id}`).
    #[schema(value_type = Option<Object>)]
    pub result: Option<Value>,
}

fn view(id: &str, j: &Job, with_result: bool) -> JobView {
    JobView {
        id: id.into(),
        status: j.status,
        path: j.path.clone(),
        started: j.started.clone(),
        finished: j.finished.clone(),
        error: j.error.clone(),
        result: if with_result { j.result.clone() } else { None },
    }
}

fn stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[utoipa::path(post, path = "/rules/test/jobs", tag = "jobs", request_body = crate::rules::TestRequest,
    description = "Same as `POST /rules/test`, in the background (limit `API_JOB_TIMEOUT_SECS`). Poll `GET /jobs/{id}`.",
    responses((status = 202, body = JobView), (status = 429, description = "Too many tests running")))]
pub async fn start(State(app): State<Arc<App>>, Json(req): Json<TestRequest>) -> Res<(StatusCode, Json<JobView>)> {
    let id = uuid::Uuid::new_v4().simple().to_string();
    {
        let mut jobs = app.jobs.lock().unwrap();
        if jobs.values().filter(|j| j.status == JobStatus::Running).count() >= MAX_RUNNING {
            return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, format!("{MAX_RUNNING} tests are already running")));
        }
        // Forget old finished jobs, then the oldest ones beyond KEEP.
        jobs.retain(|_, j| j.finished_at.is_none_or(|t| t.elapsed() < TTL));
        while jobs.len() >= KEEP {
            let Some(oldest) = jobs.iter().filter(|(_, j)| j.finished_at.is_some()).min_by_key(|(_, j)| j.finished_at).map(|(k, _)| k.clone()) else { break };
            jobs.remove(&oldest);
        }
        jobs.insert(id.clone(), Job { status: JobStatus::Running, path: req.path.clone(), started: stamp(), finished: None, finished_at: None, result: None, error: None, abort: None });
    }
    let (app2, id2) = (app.clone(), id.clone());
    let handle = tokio::spawn(async move {
        let r = rules::run_test(&app2, req, app2.cfg.job_timeout_secs).await;
        let mut jobs = app2.jobs.lock().unwrap();
        if let Some(j) = jobs.get_mut(&id2).filter(|j| j.status == JobStatus::Running) {
            match r {
                Ok(v) => (j.status, j.result) = (JobStatus::Done, Some(v)),
                Err(e) => (j.status, j.error) = (JobStatus::Failed, Some(e.1)),
            }
            (j.finished, j.finished_at, j.abort) = (Some(stamp()), Some(Instant::now()), None);
        }
    });
    let mut jobs = app.jobs.lock().unwrap();
    let j = jobs.get_mut(&id).expect("just inserted");
    if j.status == JobStatus::Running {
        j.abort = Some(handle.abort_handle());
    }
    Ok((StatusCode::ACCEPTED, Json(view(&id, j, false))))
}

#[utoipa::path(get, path = "/jobs", tag = "jobs", responses((status = 200, body = Vec<JobView>)))]
pub async fn list(State(app): State<Arc<App>>) -> Json<Vec<JobView>> {
    let jobs = app.jobs.lock().unwrap();
    let mut v: Vec<JobView> = jobs.iter().map(|(id, j)| view(id, j, false)).collect();
    v.sort_by(|a, b| b.started.cmp(&a.started));
    Json(v)
}

#[utoipa::path(get, path = "/jobs/{id}", tag = "jobs", params(("id" = String, Path)),
    responses((status = 200, body = JobView), (status = 404)))]
pub async fn get(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res<Json<JobView>> {
    let jobs = app.jobs.lock().unwrap();
    jobs.get(&id).map(|j| Json(view(&id, j, true))).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no such job"))
}

#[utoipa::path(delete, path = "/jobs/{id}", tag = "jobs", params(("id" = String, Path)),
    description = "Cancels a running test (the `elastalert` process is killed), or forgets a finished one.",
    responses((status = 200, body = JobView), (status = 404)))]
pub async fn cancel(State(app): State<Arc<App>>, Path(id): Path<String>) -> Res<Json<JobView>> {
    let mut jobs = app.jobs.lock().unwrap();
    let j = jobs.get_mut(&id).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no such job"))?;
    if j.status == JobStatus::Running {
        if let Some(a) = j.abort.take() {
            a.abort();
        }
        (j.status, j.finished, j.finished_at) = (JobStatus::Cancelled, Some(stamp()), Some(Instant::now()));
        return Ok(Json(view(&id, j, false)));
    }
    let v = view(&id, j, false);
    jobs.remove(&id);
    Ok(Json(v))
}
