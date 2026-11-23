use axum::{Json, http::StatusCode, response::{IntoResponse, Response}};
use serde_json::json;

pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn new(s: StatusCode, m: impl Into<String>) -> Self {
        ApiError(s, m.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

/// Anything unexpected (Elasticsearch down, disk error) is a 502/500 with the cause.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

pub type Res<T> = Result<T, ApiError>;
