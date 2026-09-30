//! File-related route handlers

use crate::services::watcher;
use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use std::io::ErrorKind;
use std::path::{Component, Path as FilePath};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// List all KDBX files in the configured database directory.
pub async fn list_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut files = state.kdbx_files.read().await.clone();
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Json(files)
}

/// Download one indexed database by its opaque identifier.
pub async fn download_file(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let path = {
        let files = state.kdbx_files.read().await;
        files
            .iter()
            .find(|file| file.id == id)
            .map(|file| file.path.clone())
    };
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match tokio::fs::read(path).await {
        Ok(contents) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            contents,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Create one database without replacing an existing file.
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    body: Body,
) -> Response {
    if !valid_database_name(&name) {
        return (StatusCode::BAD_REQUEST, "expected a .kdbx file name").into_response();
    }
    let Some(directory) = &state.config.storage.database_directory else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "database storage is not configured",
        )
            .into_response();
    };
    let destination = directory.join(&name);
    let mut file = match tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&destination)
        .await
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return (
                StatusCode::CONFLICT,
                "a database with this name already exists",
            )
                .into_response();
        }
        Err(error) => {
            tracing::error!("Failed to create {:?}: {}", destination, error);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut stream = body.into_data_stream();
    while let Some(result) = stream.next().await {
        let chunk = match result {
            Ok(chunk) => chunk,
            Err(error) => {
                tracing::warn!("Upload body failed for {:?}: {}", destination, error);
                drop(file);
                let _ = tokio::fs::remove_file(&destination).await;
                return (StatusCode::BAD_REQUEST, "failed to read upload body").into_response();
            }
        };
        if let Err(error) = file.write_all(&chunk).await {
            tracing::error!("Failed to write {:?}: {}", destination, error);
            drop(file);
            let _ = tokio::fs::remove_file(&destination).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if let Err(error) = file.sync_all().await {
        tracing::error!("Failed to sync {:?}: {}", destination, error);
        drop(file);
        let _ = tokio::fs::remove_file(&destination).await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    drop(file);

    if let Err(error) = watcher::index_file(&state, &destination).await {
        tracing::error!(
            "Failed to index uploaded database {:?}: {}",
            destination,
            error
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    StatusCode::CREATED.into_response()
}

/// List all detected conflicts.
pub async fn list_conflicts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let conflicts = state.conflicts.read().await;
    Json(conflicts.clone())
}

fn valid_database_name(name: &str) -> bool {
    let path = FilePath::new(name);
    path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
        && !name.contains('\\')
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("kdbx"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_state(directory: &FilePath) -> Arc<AppState> {
        let mut config = Config::default();
        config.storage.database_directory = Some(directory.to_path_buf());
        Arc::new(AppState::new(config))
    }

    #[test]
    fn accepts_only_top_level_database_names() {
        assert!(valid_database_name("passwords.kdbx"));
        assert!(valid_database_name("PASSWORDS.KDBX"));
        assert!(!valid_database_name("../passwords.kdbx"));
        assert!(!valid_database_name("nested/passwords.kdbx"));
        assert!(!valid_database_name(r"nested\passwords.kdbx"));
        assert!(!valid_database_name("passwords.txt"));
    }

    #[tokio::test]
    async fn upload_creates_once_without_replacing_contents() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());

        let response = upload_file(
            State(state.clone()),
            Path("passwords.kdbx".to_string()),
            Body::from("first"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = upload_file(
            State(state),
            Path("passwords.kdbx".to_string()),
            Body::from("second"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            tokio::fs::read(directory.path().join("passwords.kdbx"))
                .await
                .expect("read uploaded database"),
            b"first"
        );
    }
}
