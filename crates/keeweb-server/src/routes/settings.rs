//! Settings route handlers

use crate::state::AppState;
use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct SettingsResponse {
    pub database_directory: Option<String>,
    pub syncthing_enabled: bool,
    pub conflict_pattern: String,
}

/// Get current settings
pub async fn get_settings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = SettingsResponse {
        database_directory: state
            .config
            .storage
            .database_directory
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        syncthing_enabled: state.config.syncthing.enabled,
        conflict_pattern: state.config.syncthing.conflict_pattern.clone(),
    };

    Json(settings)
}
