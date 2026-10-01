//! File-related route handlers

use crate::services::watcher;
use crate::state::AppState;
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, ETAG, IF_MATCH},
    },
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::path::{Component, Path as FilePath, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// Identity and revision of a database after a successful write.
#[derive(Debug, Serialize)]
pub struct WrittenFile {
    pub id: String,
    pub name: String,
    pub revision: String,
}

/// Body of a 412 response: the revision the client must merge against.
#[derive(Debug, Serialize)]
pub struct CurrentRevision {
    pub revision: String,
}

/// List all KDBX files in the configured database directory.
pub async fn list_files(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut files = state.kdbx_files.read().await.clone();
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Json(files)
}

/// Path and name of the indexed database with this identifier.
async fn find_file(state: &AppState, id: &str) -> Option<(PathBuf, String)> {
    let files = state.kdbx_files.read().await;
    files
        .iter()
        .find(|file| file.id == id)
        .map(|file| (PathBuf::from(&file.path), file.name.clone()))
}

/// Download one indexed database by its opaque identifier. The `ETag` is the
/// revision of exactly the returned bytes.
pub async fn download_file(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Some((path, _)) = find_file(&state, &id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match tokio::fs::read(path).await {
        Ok(contents) => {
            let etag = entity_tag(&watcher::revision_of(&contents));
            (
                StatusCode::OK,
                [
                    (
                        CONTENT_TYPE,
                        HeaderValue::from_static("application/octet-stream"),
                    ),
                    (ETAG, etag),
                ],
                contents,
            )
                .into_response()
        }
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

    let mut hasher = Sha256::new();
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
        hasher.update(&chunk);
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
    (
        StatusCode::CREATED,
        Json(WrittenFile {
            id: watcher::file_id(&destination),
            name,
            revision: watcher::hex_lower(&hasher.finalize()),
        }),
    )
        .into_response()
}

/// Replace an existing database if its current revision matches `If-Match`.
///
/// The body is first written and synced to a temporary file next to the
/// target, so a slow upload never holds the per-file lock. Under the lock the
/// current revision is checked and the temporary file is renamed over the
/// target, which readers observe as either the old or the new version.
pub async fn replace_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some((path, name)) = find_file(&state, &id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(if_match) = headers.get(IF_MATCH) else {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            "If-Match with the current revision is required",
        )
            .into_response();
    };
    let expected = parse_entity_tag(if_match);
    let Some(directory) = path.parent().map(FilePath::to_path_buf) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let temp = temp_path(&directory, &name);

    let revision = match write_temp_file(&temp, body).await {
        Ok(revision) => revision,
        Err(response) => {
            let _ = tokio::fs::remove_file(&temp).await;
            return response;
        }
    };

    let lock = state.replace_lock(&path);
    let guard = lock.lock().await;
    if let Err(response) = commit_replace(&path, &directory, &temp, expected.as_deref()).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return response;
    }
    // Index before releasing the lock so the next writer's list/download view
    // already reflects this version.
    if let Err(error) = watcher::index_file(&state, &path).await {
        tracing::warn!("Failed to index replaced database {:?}: {}", path, error);
    }
    drop(guard);

    (
        StatusCode::OK,
        Json(WrittenFile {
            id: watcher::file_id(&path),
            name,
            revision,
        }),
    )
        .into_response()
}

/// Stream the body into a new private file and sync it. Returns the revision of
/// the written bytes.
async fn write_temp_file(temp: &FilePath, body: Body) -> Result<String, Response> {
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(temp).await.map_err(|error| {
        tracing::error!("Failed to create {:?}: {}", temp, error);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let mut hasher = Sha256::new();
    let mut stream = body.into_data_stream();
    while let Some(result) = stream.next().await {
        let chunk = result.map_err(|error| {
            tracing::warn!("Replace body failed for {:?}: {}", temp, error);
            (StatusCode::BAD_REQUEST, "failed to read upload body").into_response()
        })?;
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|error| {
            tracing::error!("Failed to write {:?}: {}", temp, error);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
    }
    file.sync_all().await.map_err(|error| {
        tracing::error!("Failed to sync {:?}: {}", temp, error);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    Ok(watcher::hex_lower(&hasher.finalize()))
}

/// Check the target's current revision and rename the synced temporary file
/// over it. Must run under the target's replace lock.
async fn commit_replace(
    path: &FilePath,
    directory: &FilePath,
    temp: &FilePath,
    expected: Option<&str>,
) -> Result<(), Response> {
    let (current, metadata) = match tokio::fs::read(path).await {
        Ok(contents) => (
            watcher::revision_of(&contents),
            tokio::fs::metadata(path).await,
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StatusCode::NOT_FOUND.into_response());
        }
        Err(error) => {
            tracing::error!("Failed to read {:?}: {}", path, error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
    if expected != Some(current.as_str()) {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(CurrentRevision { revision: current }),
        )
            .into_response());
    }

    // Keep the target's permission bits; the temporary file is created 0600.
    if let Ok(metadata) = metadata {
        if let Err(error) = tokio::fs::set_permissions(temp, metadata.permissions()).await {
            tracing::warn!("Failed to copy permissions to {:?}: {}", temp, error);
        }
    }
    if let Err(error) = tokio::fs::rename(temp, path).await {
        tracing::error!("Failed to rename {:?} over {:?}: {}", temp, path, error);
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    // The rename is durable only once the directory entry is synced. The
    // replace already happened, but report failure so the client does not
    // assume durability; a retry sees the new revision and merges.
    let synced = match tokio::fs::File::open(directory).await {
        Ok(handle) => handle.sync_all().await,
        Err(error) => Err(error),
    };
    if let Err(error) = synced {
        tracing::error!("Failed to sync directory {:?}: {}", directory, error);
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    Ok(())
}

/// Temporary file for replacing `name`. The `.tmp` suffix keeps it out of
/// the database index and the leading dot hides it from directory listings.
fn temp_path(directory: &FilePath, name: &str) -> PathBuf {
    directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()))
}

fn entity_tag(revision: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{revision}\"")).expect("hex revision is a valid header value")
}

/// Revision named by an `If-Match` value. Accepts a quoted strong entity tag
/// or a bare revision; weak tags never match because `If-Match` requires
/// strong comparison.
fn parse_entity_tag(value: &HeaderValue) -> Option<String> {
    let value = value.to_str().ok()?.trim();
    let revision = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    Some(revision.to_ascii_lowercase())
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
    use serde_json::Value;

    const FIRST_REVISION: &str = "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e";
    const SECOND_REVISION: &str =
        "16367aacb67a4a017c8da8ab95682ccb390863780f7114dda0a0e0c55644c7c4";

    async fn body_bytes(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body")
            .to_vec()
    }

    async fn body_json(response: Response) -> Value {
        serde_json::from_slice(&body_bytes(response).await).expect("parse response JSON")
    }

    /// Create `passwords.kdbx` containing "first" and return its id.
    async fn create_database(state: &Arc<AppState>) -> String {
        let response = upload_file(
            State(state.clone()),
            Path("passwords.kdbx".to_string()),
            Body::from("first"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(created["name"], "passwords.kdbx");
        assert_eq!(created["revision"], FIRST_REVISION);
        created["id"].as_str().expect("id is a string").to_string()
    }

    async fn replace(
        state: &Arc<AppState>,
        id: &str,
        if_match: Option<&str>,
        contents: &'static str,
    ) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(value) = if_match {
            headers.insert(IF_MATCH, HeaderValue::from_str(value).unwrap());
        }
        replace_file(
            State(state.clone()),
            Path(id.to_string()),
            headers,
            Body::from(contents),
        )
        .await
    }

    async fn listed(state: &Arc<AppState>) -> Value {
        body_json(list_files(State(state.clone())).await.into_response()).await
    }

    fn directory_entries(directory: &FilePath) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

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
    #[tokio::test]
    async fn list_and_download_report_the_same_revision() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        let id = create_database(&state).await;

        let files = listed(&state).await;
        assert_eq!(files[0]["id"], id.as_str());
        assert_eq!(files[0]["revision"], FIRST_REVISION);

        let response = download_file(State(state), Path(id)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[ETAG],
            format!("\"{FIRST_REVISION}\"").as_str()
        );
        assert_eq!(body_bytes(response).await, b"first");
    }

    #[tokio::test]
    async fn replace_with_current_revision_swaps_contents_and_revision() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        let id = create_database(&state).await;

        let response = replace(
            &state,
            &id,
            Some(&format!("\"{FIRST_REVISION}\"")),
            "second",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let written = body_json(response).await;
        assert_eq!(written["id"], id.as_str());
        assert_eq!(written["name"], "passwords.kdbx");
        assert_eq!(written["revision"], SECOND_REVISION);

        assert_eq!(
            std::fs::read(directory.path().join("passwords.kdbx")).unwrap(),
            b"second"
        );
        let files = listed(&state).await;
        assert_eq!(files.as_array().unwrap().len(), 1);
        assert_eq!(files[0]["revision"], SECOND_REVISION);
        assert_eq!(files[0]["size"], 6);
        let response = download_file(State(state), Path(id)).await;
        assert_eq!(
            response.headers()[ETAG],
            format!("\"{SECOND_REVISION}\"").as_str()
        );
        assert_eq!(directory_entries(directory.path()), vec!["passwords.kdbx"]);
    }

    #[tokio::test]
    async fn replace_with_stale_revision_is_rejected_and_keeps_contents() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        let id = create_database(&state).await;
        let accepted = replace(
            &state,
            &id,
            Some(&format!("\"{FIRST_REVISION}\"")),
            "second",
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::OK);

        let response = replace(&state, &id, Some(&format!("\"{FIRST_REVISION}\"")), "third").await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(body_json(response).await["revision"], SECOND_REVISION);

        let weak = replace(
            &state,
            &id,
            Some(&format!("W/\"{SECOND_REVISION}\"")),
            "third",
        )
        .await;
        assert_eq!(weak.status(), StatusCode::PRECONDITION_FAILED);

        assert_eq!(
            std::fs::read(directory.path().join("passwords.kdbx")).unwrap(),
            b"second"
        );
        assert_eq!(listed(&state).await[0]["revision"], SECOND_REVISION);
        assert_eq!(directory_entries(directory.path()), vec!["passwords.kdbx"]);
    }

    #[tokio::test]
    async fn replace_without_if_match_requires_precondition() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        let id = create_database(&state).await;

        let response = replace(&state, &id, None, "second").await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(
            std::fs::read(directory.path().join("passwords.kdbx")).unwrap(),
            b"first"
        );
        assert_eq!(directory_entries(directory.path()), vec!["passwords.kdbx"]);
    }

    #[tokio::test]
    async fn replace_of_unknown_id_is_not_found() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        create_database(&state).await;

        let response = replace(
            &state,
            "unknown",
            Some(&format!("\"{FIRST_REVISION}\"")),
            "second",
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(directory_entries(directory.path()), vec!["passwords.kdbx"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_replaces_from_the_same_revision_accept_exactly_one() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let state = test_state(directory.path());
        let id = create_database(&state).await;
        let if_match = format!("\"{FIRST_REVISION}\"");

        let mut tasks = Vec::new();
        for contents in ["second", "third", "fourth", "fifth"] {
            let state = state.clone();
            let id = id.clone();
            let if_match = if_match.clone();
            tasks.push(tokio::spawn(async move {
                replace(&state, &id, Some(&if_match), contents)
                    .await
                    .status()
            }));
        }
        let mut statuses = Vec::new();
        for task in tasks {
            statuses.push(task.await.unwrap());
        }

        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
                .count(),
            3
        );
        assert_eq!(directory_entries(directory.path()), vec!["passwords.kdbx"]);
    }
}
