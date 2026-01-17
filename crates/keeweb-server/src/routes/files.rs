//! File-related route handlers

use crate::state::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;

/// List all KDBX files in watched directories
pub async fn list_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let files = state.kdbx_files.read().await;
    Json(files.clone())
}

/// Download a specific file
pub async fn download_file(
    State(_state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    // Decode the path
    let decoded_path = urlencoding::decode(&path)
        .map(|s| s.into_owned())
        .unwrap_or(path);

    // Security: Validate the path is within allowed directories
    // TODO: Implement proper path validation

    match tokio::fs::read(&decoded_path).await {
        Ok(contents) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            contents,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// List all detected conflicts
pub async fn list_conflicts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let conflicts = state.conflicts.read().await;
    Json(conflicts.clone())
}

mod urlencoding {
    pub fn decode(input: &str) -> Result<std::borrow::Cow<'_, str>, ()> {
        // Simple URL decoding
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }

        Ok(std::borrow::Cow::Owned(result))
    }
}
