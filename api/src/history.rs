//! Read side of the writeback indices (alerts, runs, errors) and the silences.

use crate::{App, auth::Writer, error::{ApiError, Res}, rules};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

type S = State<Arc<App>>;

#[derive(Serialize, ToSchema)]
pub struct Page {
    pub total: u64,
    /// Documents as stored in Elasticsearch, with `_id` added.
    #[schema(value_type = Vec<Object>)]
    pub items: Vec<Value>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// Exact rule name.
    pub rule: Option<String>,
    /// Only documents at or after this ISO8601 time.
    pub since: Option<String>,
    /// Only documents before this ISO8601 time.
    pub until: Option<String>,
    /// Alerts only: `true` = delivered, `false` = still pending.
    pub sent: Option<bool>,
    /// Page size (default 50, max 1000).
    pub size: Option<u32>,
    pub offset: Option<u32>,
}

/// Search body: newest first by `time_field`, filters from the query.
fn body(q: &HistoryQuery, time_field: &str) -> Value {
    let mut f = vec![];
    if let Some(r) = &q.rule {
        f.push(json!({"term": {"rule_name": r}}));
    }
    if let Some(s) = q.sent {
        f.push(json!({"term": {"alert_sent": s}}));
    }
    let mut range = serde_json::Map::new();
    if let Some(s) = &q.since {
        range.insert("gte".into(), json!(s));
    }
    if let Some(u) = &q.until {
        range.insert("lt".into(), json!(u));
    }
    if !range.is_empty() {
        f.push(json!({"range": {time_field: range}}));
    }
    json!({
        "query": {"bool": {"filter": f}},
        "sort": [{time_field: {"order": "desc", "unmapped_type": "date"}}],
        "size": q.size.unwrap_or(50).min(1000),
        "from": q.offset.unwrap_or(0),
    })
}

async fn page(app: &App, index: String, q: &HistoryQuery, time_field: &str) -> Res<Json<Value>> {
    Ok(Json(app.es.search(&index, body(q, time_field)).await?))
}

#[utoipa::path(get, path = "/alerts", params(HistoryQuery), tag = "alerts", responses((status = 200, body = Page)))]
pub async fn alerts(State(app): S, Query(q): Query<HistoryQuery>) -> Res<Json<Value>> {
    page(&app, app.cfg.wb.clone(), &q, "alert_time").await
}

#[utoipa::path(get, path = "/alerts/pending", tag = "alerts",
    description = "Alerts not delivered yet: waiting for their aggregation window or for a retry.", responses((status = 200, body = Page)))]
pub async fn pending(State(app): S, Query(mut q): Query<HistoryQuery>) -> Res<Json<Value>> {
    q.sent = Some(false);
    page(&app, app.cfg.wb.clone(), &q, "alert_time").await
}

#[utoipa::path(get, path = "/alerts/{id}", tag = "alerts",
    params(("id" = String, Path, description = "Document `_id`")),
    responses((status = 200, body = Object), (status = 404)))]
pub async fn alert(State(app): S, Path(id): Path<String>) -> Res<Json<Value>> {
    match app.es.get_doc(&app.cfg.wb, &id).await? {
        Some(d) => Ok(Json(d)),
        None => Err(ApiError::new(StatusCode::NOT_FOUND, "no such alert")),
    }
}

#[utoipa::path(get, path = "/runs", params(HistoryQuery), tag = "alerts",
    description = "One document per rule run (`_status` index): query range, hits, matches, time taken.", responses((status = 200, body = Page)))]
pub async fn runs(State(app): S, Query(q): Query<HistoryQuery>) -> Res<Json<Value>> {
    page(&app, format!("{}_status", app.cfg.wb), &q, "@timestamp").await
}

#[utoipa::path(get, path = "/errors", params(HistoryQuery), tag = "alerts",
    description = "Errors the daemon recorded (`_error` index), tracebacks included.", responses((status = 200, body = Page)))]
pub async fn errors(State(app): S, Query(q): Query<HistoryQuery>) -> Res<Json<Value>> {
    page(&app, format!("{}_error", app.cfg.wb), &q, "@timestamp").await
}

#[utoipa::path(get, path = "/silences", tag = "silences",
    description = "Silences still running (`until` in the future).", responses((status = 200, body = Page)))]
pub async fn silences(State(app): S) -> Res<Json<Value>> {
    let b = json!({"query": {"bool": {"filter": [{"range": {"until": {"gt": "now"}}}], "must_not": [{"term": {"lifted": true}}]}}, "sort": [{"until": {"order": "desc", "unmapped_type": "date"}}], "size": 1000});
    Ok(Json(app.es.search(&format!("{}_silence", app.cfg.wb), b).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct NewSilence {
    /// Rule name.
    pub rule: String,
    /// ElastAlert `--silence` syntax: `<unit>=<number>`, unit in seconds, minutes, hours, days, weeks. E.g. `hours=2`.
    pub duration: String,
    /// Silence only the matches of this `query_key` value.
    pub query_key_value: Option<String>,
}

fn seconds(d: &str) -> Option<i64> {
    let (unit, n) = d.split_once('=')?;
    let n: i64 = n.trim().parse().ok().filter(|n| *n > 0)?;
    let per = match unit.trim() {
        "seconds" => 1,
        "minutes" => 60,
        "hours" => 3600,
        "days" => 86_400,
        "weeks" => 604_800,
        _ => return None,
    };
    n.checked_mul(per).filter(|s| *s <= 366 * 86_400)
}

#[utoipa::path(post, path = "/silences", tag = "silences", request_body = NewSilence,
    description = "Same document as `elastalert --silence`. The daemon reads it at its next maintenance tick (about `run_every`).",
    responses((status = 201, body = Object), (status = 404, description = "Unknown rule"), (status = 400, description = "Bad duration")))]
pub async fn silence(_: Writer, State(app): S, Json(s): Json<NewSilence>) -> Res<(StatusCode, Json<Value>)> {
    let secs = seconds(&s.duration).ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "duration must look like hours=2 (max 366 days)"))?;
    let rule = rules::scan(&app).await?.into_iter().find(|r| r.name == s.rule)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("no rule named {}", s.rule)))?;
    let key = match &s.query_key_value {
        Some(v) => format!("{}.{v}", rule.realert_key),
        None => format!("{}._silence", rule.name),
    };
    let now = chrono::Utc::now();
    let doc = json!({
        "exponent": 0,
        "rule_name": key,
        "@timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "until": (now + chrono::Duration::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    });
    app.es.index(&format!("{}_silence", app.cfg.wb), &doc).await?;
    Ok((StatusCode::CREATED, Json(doc)))
}

#[utoipa::path(delete, path = "/silences/{id}", tag = "silences", params(("id" = String, Path, description = "`_id` from `GET /silences`")),
    description = "Lifts the silence of that rule (all its running silence documents). The daemon forgets it at its next maintenance tick (about `run_every`).",
    responses((status = 200, body = Object), (status = 404, description = "No such silence")))]
pub async fn lift(_: Writer, State(app): S, Path(id): Path<String>) -> Res<Json<Value>> {
    let index = format!("{}_silence", app.cfg.wb);
    let doc = app.es.get_doc(&index, &id).await?.filter(|d| d["lifted"] != json!(true)).ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no such silence"))?;
    let key = doc["rule_name"].as_str().ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no such silence"))?.to_string();
    let q = json!({"query": {"bool": {"filter": [{"term": {"rule_name": key}}, {"range": {"until": {"gt": "now"}}}], "must_not": [{"term": {"lifted": true}}]}}});
    let (status, resp) = app.es.raw(reqwest::Method::POST, &format!("{index}/_delete_by_query?refresh=true&conflicts=proceed"), Some(&q)).await?;
    if !status.is_success() {
        return Err(ApiError::new(StatusCode::BAD_GATEWAY, format!("Elasticsearch answered {status}: {resp}")));
    }
    // The daemon keeps silences in memory and never shortens one it knows; this marker tells it to drop the key.
    let now = chrono::Utc::now();
    let marker = json!({
        "exponent": 0, "rule_name": key, "lifted": true,
        "@timestamp": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "until": (now + chrono::Duration::hours(24)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    });
    app.es.index(&index, &marker).await?;
    Ok(Json(json!({"rule_name": key, "deleted": resp["deleted"].as_u64().unwrap_or(0)})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(seconds("hours=2"), Some(7200));
        assert_eq!(seconds("minutes = 5"), Some(300));
        for bad in ["2h", "hours=0", "hours=-1", "years=1", "days=400", "hours=x"] {
            assert_eq!(seconds(bad), None, "{bad}");
        }
    }

    #[test]
    fn query_body() {
        let q = HistoryQuery { rule: Some("r".into()), since: Some("2026-01-01T00:00:00Z".into()), until: None, sent: Some(false), size: Some(5000), offset: None };
        let b = body(&q, "alert_time");
        assert_eq!(b["size"], 1000);
        assert_eq!(b["query"]["bool"]["filter"].as_array().unwrap().len(), 3);
    }
}
