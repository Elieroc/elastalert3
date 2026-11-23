//! Bearer-token auth with two roles, plus the audit log of everything that is not a plain read.

use crate::{App, error::ApiError};
use axum::{
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    Read,
    Write,
}

/// Constant-time comparison.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

pub fn role_of(token: &str, read: &str, write: &str) -> Option<Role> {
    // Both comparisons always run.
    let (w, r) = (same(token, write), same(token, read));
    if w { Some(Role::Write) } else if r { Some(Role::Read) } else { None }
}

fn public(path: &str) -> bool {
    path == "/health" || path.starts_with("/swagger-ui") || path.starts_with("/api-docs")
}

pub async fn layer(State(app): State<Arc<App>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    let role = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| role_of(t, &app.cfg.read_token, &app.cfg.write_token));
    let resp = match role {
        Some(r) => {
            req.extensions_mut().insert(r);
            next.run(req).await
        }
        None if public(&path) => next.run(req).await,
        None => ApiError::new(StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response(),
    };
    let status = resp.status();
    if !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        // One JSON line on stdout (docker logs). Request bodies and tokens are never logged.
        println!(
            "{}",
            serde_json::json!({
                "audit": true,
                "ts": chrono::Utc::now().to_rfc3339(),
                "ip": addr.ip().to_string(),
                "role": role.map(|r| format!("{r:?}").to_lowercase()),
                "method": method.as_str(),
                "path": path,
                "status": status.as_u16(),
            })
        );
    }
    resp
}

/// Handler argument that requires the write role.
pub struct Writer;

impl<S: Send + Sync> FromRequestParts<S> for Writer {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Writer, ApiError> {
        match parts.extensions.get::<Role>() {
            Some(Role::Write) => Ok(Writer),
            _ => Err(ApiError::new(StatusCode::FORBIDDEN, "this endpoint needs the write token")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert_eq!(role_of("w", "r", "w"), Some(Role::Write));
        assert_eq!(role_of("r", "r", "w"), Some(Role::Read));
        assert_eq!(role_of("x", "r", "w"), None);
        assert_eq!(role_of("", "r", "w"), None);
        assert!(Role::Write > Role::Read);
    }
}
