//! File system watcher service

use crate::state::{AppState, ConflictInfo, FileEvent, KdbxFileInfo};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
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

async fn handle_event(state: &Arc<AppState>, event: Event) {
    use notify::EventKind;

    for path in event.paths {
        if !is_kdbx_path(&path) {
            continue;
        }

        let path_string = path.to_string_lossy().to_string();
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                if let Err(error) = index_file(state, &path).await {
                    tracing::warn!("Failed to index {:?}: {}", path, error);
                }
            }
            EventKind::Remove(_) => {
                if is_conflict_file(&path_string, &state.config.syncthing.conflict_pattern) {
                    state.remove_conflict(&path_string).await;
                } else {
                    state.remove_kdbx_file(&path_string).await;
                }
                state.send_event(FileEvent::FileDeleted { path: path_string });
            }
            _ => {}
        }
    }
}

pub(crate) async fn index_file(
    state: &Arc<AppState>,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_kdbx_path(path) {
        return Ok(());
    }

    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.file_type().is_file() {
        return Ok(());
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
        return Ok(());
    }

    let info = KdbxFileInfo {
        id: URL_SAFE_NO_PAD.encode(path_string.as_bytes()),
        path: path_string.clone(),
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default(),
        size: metadata.len(),
        modified: metadata
            .modified()
            .ok()
            .map(chrono::DateTime::from)
            .unwrap_or_else(Utc::now),
    };
    state.add_kdbx_file(info).await;
    state.send_event(FileEvent::FileChanged { path: path_string });
    Ok(())
}

async fn scan_directory(
    state: &Arc<AppState>,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut entries = tokio::fs::read_dir(directory).await?;

    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            index_file(state, &entry.path()).await?;
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
