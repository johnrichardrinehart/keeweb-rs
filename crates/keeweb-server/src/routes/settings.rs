//! Settings route handlers

use crate::state::AppState;
use axum::{Json, extract::State, response::IntoResponse};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub struct SettingsResponse {
    pub watch_directories: Vec<String>,
    pub syncthing_enabled: bool,
    pub conflict_pattern: String,
}

/// Get current settings
pub async fn get_settings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = SettingsResponse {
        watch_directories: state
            .config
            .storage
            .watch_directories
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        syncthing_enabled: state.config.syncthing.enabled,
        conflict_pattern: state.config.syncthing.conflict_pattern.clone(),
    };

    Json(settings)
}
