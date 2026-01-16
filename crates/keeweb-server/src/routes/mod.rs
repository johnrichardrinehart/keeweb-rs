//! HTTP route handlers

pub mod files;
pub mod settings;
pub mod sse;

use axum::http::StatusCode;

/// Health check endpoint
pub async fn health() -> StatusCode {
    StatusCode::OK
}
