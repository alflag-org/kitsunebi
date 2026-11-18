//! Redacted transport errors.
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use std::fmt;

/// Errors exposed by the HTTP boundary. Internal details are intentionally not
/// carried into the response body or logs by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// No valid Cloudflare Access assertion was supplied.
    Unauthorized,
    /// The mapped actor lacks the required permission or service scope.
    Forbidden,
    /// The request failed a transport-level validation.
    InvalidRequest(&'static str),
    /// The requested object does not exist.
    NotFound,
    /// A stale revision, duplicate idempotency key, or conflicting operation.
    Conflict,
    /// Request or upload exceeds the configured limit.
    PayloadTooLarge,
    /// Too many dangerous requests for the verified actor.
    RateLimited,
    /// A configured security requirement is unavailable.
    SecurityMisconfigured,
    /// A downstream port rejected the operation without exposing its details.
    Backend,
    /// The authenticated application does not provide a requested capability.
    Unsupported,
    /// A relay reached its frame, idle, or lifetime limit.
    RelayClosed,
}
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::InvalidRequest(m) => m,
            Self::NotFound => "not found",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload too large",
            Self::RateLimited => "rate limited",
            Self::SecurityMisconfigured => "security misconfigured",
            Self::Backend => "backend unavailable",
            Self::Unsupported => "unsupported operation",
            Self::RelayClosed => "relay closed",
        })
    }
}
impl std::error::Error for ApiError {}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::SecurityMisconfigured => {
                (StatusCode::INTERNAL_SERVER_ERROR, "security_misconfigured")
            }
            Self::Backend => (StatusCode::BAD_GATEWAY, "backend_unavailable"),
            Self::Unsupported => (StatusCode::UNPROCESSABLE_ENTITY, "unsupported"),
            Self::RelayClosed => (StatusCode::GATEWAY_TIMEOUT, "relay_closed"),
        };
        (status, Json(json!({"error": code}))).into_response()
    }
}
