//! File system watcher service

use crate::state::{AppState, ConflictInfo, FileEvent, KdbxFileInfo};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Start the file system watcher
pub async fn start_watcher(
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = state
        .config
        .storage
        .database_directory
        .clone()
        .ok_or_else(|| std::io::Error::other("database_directory is not configured"))?;
    let (tx, mut rx) = mpsc::channel::<Result<Event, notify::Error>>(100);

    scan_directory(&state, &directory).await?;

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        Config::default(),
    )?;
    watcher.watch(&directory, RecursiveMode::NonRecursive)?;
    tracing::info!("Watching database directory: {:?}", directory);

    let state_clone = state.clone();
    tokio::spawn(async move {
        let _watcher = watcher;

        while let Some(result) = rx.recv().await {
            match result {
                Ok(event) => {
                    handle_event(&state_clone, event).await;
                }
                Err(error) => {
                    tracing::error!("Watcher error: {:?}", error);
                }
            }
        }
    });

    Ok(())
}

/// Reconcile the index with the current on-disk state of every path in the
/// event. Renames arrive as Modify events for both the old and new name, so the
/// event kind alone does not say whether a path still exists.
async fn handle_event(state: &Arc<AppState>, event: Event) {
    use notify::EventKind;

    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return;
    }
    for path in event.paths {
        if !is_kdbx_path(&path) {
            continue;
        }
        match index_file(state, &path).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => forget_file(state, &path).await,
            Err(error) => tracing::warn!("Failed to index {:?}: {}", path, error),
        }
    }
}

async fn forget_file(state: &Arc<AppState>, path: &Path) {
    let path_string = path.to_string_lossy().to_string();
    if is_conflict_file(&path_string, &state.config.syncthing.conflict_pattern) {
        state.remove_conflict(&path_string).await;
    } else {
        state.remove_kdbx_file(&path_string).await;
    }
    state.send_event(FileEvent::FileDeleted { path: path_string });
}

/// Index one database or conflict file. Returns the indexed database entry, or
/// `None` when the path is not an indexable database.
pub(crate) async fn index_file(
    state: &Arc<AppState>,
    path: &Path,
) -> std::io::Result<Option<KdbxFileInfo>> {
    if !is_kdbx_path(path) {
        return Ok(None);
    }

    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.file_type().is_file() {
        return Ok(None);
    }

    let path_string = path.to_string_lossy().to_string();
    if is_conflict_file(&path_string, &state.config.syncthing.conflict_pattern) {
        if let Some(original) = find_original_file(&path_string) {
            state
                .add_conflict(ConflictInfo {
                    original_path: original.clone(),
                    conflict_path: path_string.clone(),
                    detected_at: Utc::now(),
                })
                .await;
            state.send_event(FileEvent::ConflictDetected {
                original,
                conflict: path_string,
            });
        }
        return Ok(None);
    }

    // Size and revision come from the same read so they always describe one
    // version of the file, even while it is being replaced.
    let contents = tokio::fs::read(path).await?;
    let info = KdbxFileInfo {
        id: file_id(path),
        path: path_string.clone(),
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        size: contents.len() as u64,
        modified: metadata
            .modified()
            .ok()
            .map(chrono::DateTime::from)
            .unwrap_or_else(Utc::now),
        revision: revision_of(&contents),
    };
    state.add_kdbx_file(info.clone()).await;
    state.send_event(FileEvent::FileChanged { path: path_string });
    Ok(Some(info))
}

/// Opaque API identifier of a database path.
pub(crate) fn file_id(path: &Path) -> String {
    URL_SAFE_NO_PAD.encode(path.to_string_lossy().as_bytes())
}

/// Revision of file contents: lowercase hex SHA-256.
pub(crate) fn revision_of(contents: &[u8]) -> String {
    hex_lower(&Sha256::digest(contents))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

async fn scan_directory(
    state: &Arc<AppState>,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut entries = tokio::fs::read_dir(directory).await?;

    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            match index_file(state, &entry.path()).await {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    Ok(())
}

fn is_kdbx_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("kdbx"))
}

/// Check if a file path matches the conflict pattern
fn is_conflict_file(path: &str, pattern: &str) -> bool {
    path.contains(pattern)
}

/// Find the original file for a conflict file
/// e.g., "passwords.sync-conflict-20240115-123456-ABCDEF.kdbx" -> "passwords.kdbx"
fn find_original_file(conflict_path: &str) -> Option<String> {
    // Find the .sync-conflict- part and remove it
    if let Some(idx) = conflict_path.find(".sync-conflict-") {
        let before = &conflict_path[..idx];
        // Find the extension after the conflict marker
        if let Some(ext_idx) = conflict_path.rfind('.') {
            let extension = &conflict_path[ext_idx..];
            return Some(format!("{}{}", before, extension));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::EventKind;
    use notify::event::{ModifyKind, RenameMode};

    fn test_state(directory: &Path) -> Arc<AppState> {
        let mut config = crate::config::Config::default();
        config.storage.database_directory = Some(directory.to_path_buf());
        Arc::new(AppState::new(config))
    }

    async fn listed_names(state: &AppState) -> Vec<String> {
        let mut names: Vec<String> = state
            .kdbx_files
            .read()
            .await
            .iter()
            .map(|file| file.name.clone())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn scan_ignores_replace_temp_files() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        std::fs::write(directory.path().join("passwords.kdbx"), b"db").unwrap();
        std::fs::write(
            directory
                .path()
                .join(".passwords.kdbx.0123456789abcdef.tmp"),
            b"partial",
        )
        .unwrap();
        let state = test_state(directory.path());

        scan_directory(&state, directory.path()).await.unwrap();

        assert_eq!(listed_names(&state).await, vec!["passwords.kdbx"]);
    }

    #[tokio::test]
    async fn rename_event_moves_index_entry_without_leaving_stale_name() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let old = directory.path().join("old.kdbx");
        let new = directory.path().join("new.kdbx");
        std::fs::write(&old, b"db").unwrap();
        let state = test_state(directory.path());
        scan_directory(&state, directory.path()).await.unwrap();

        std::fs::rename(&old, &new).unwrap();
        let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(old)
            .add_path(new);
        handle_event(&state, event).await;

        assert_eq!(listed_names(&state).await, vec!["new.kdbx"]);
    }

    #[tokio::test]
    async fn rename_over_existing_database_updates_revision() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let target = directory.path().join("passwords.kdbx");
        let temp = directory
            .path()
            .join(".passwords.kdbx.0123456789abcdef.tmp");
        std::fs::write(&target, b"first").unwrap();
        let state = test_state(directory.path());
        scan_directory(&state, directory.path()).await.unwrap();

        std::fs::write(&temp, b"second").unwrap();
        std::fs::rename(&temp, &target).unwrap();
        let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(temp)
            .add_path(target);
        handle_event(&state, event).await;

        let files = state.kdbx_files.read().await;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "passwords.kdbx");
        assert_eq!(
            files[0].revision,
            "16367aacb67a4a017c8da8ab95682ccb390863780f7114dda0a0e0c55644c7c4"
        );
    }

    #[test]
    fn test_is_conflict_file() {
        assert!(is_conflict_file(
            "passwords.sync-conflict-20240115-123456-ABCDEF.kdbx",
            ".sync-conflict-"
        ));
        assert!(!is_conflict_file("passwords.kdbx", ".sync-conflict-"));
    }

    #[test]
    fn test_find_original_file() {
        assert_eq!(
            find_original_file("passwords.sync-conflict-20240115-123456-ABCDEF.kdbx"),
            Some("passwords.kdbx".to_string())
        );
        assert_eq!(
            find_original_file("/home/user/db.sync-conflict-20240115-123456-ABC.kdbx"),
            Some("/home/user/db.kdbx".to_string())
        );
    }
}
