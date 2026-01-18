//! File system watcher service

use crate::state::{AppState, ConflictInfo, FileEvent, KdbxFileInfo};
use chrono::Utc;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Start the file system watcher
pub async fn start_watcher(
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, mut rx) = mpsc::channel::<Result<Event, notify::Error>>(100);

    // Initial scan
    for dir in &state.config.storage.watch_directories {
        if dir.exists() {
            scan_directory(&state, dir).await?;
        }
    }

    // Create watcher
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        Config::default(),
    )?;

    // Watch directories
    for dir in &state.config.storage.watch_directories {
        if dir.exists() {
            watcher.watch(dir, RecursiveMode::Recursive)?;
            tracing::info!("Watching directory: {:?}", dir);
        } else {
            tracing::warn!("Directory does not exist: {:?}", dir);
        }
    }

    // Spawn handler task
    let state_clone = state.clone();
    tokio::spawn(async move {
        // Keep watcher alive
        let _watcher = watcher;

        while let Some(result) = rx.recv().await {
            match result {
                Ok(event) => {
                    handle_event(&state_clone, event).await;
                }
                Err(e) => {
                    tracing::error!("Watcher error: {:?}", e);
                }
            }
        }
    });

    Ok(())
}

/// Handle a file system event
async fn handle_event(state: &Arc<AppState>, event: Event) {
    use notify::EventKind;

    for path in event.paths {
        let path_str = path.to_string_lossy().to_string();

        // Only care about .kdbx files
        if !path_str.ends_with(".kdbx") {
            continue;
        }

        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                // Check if this is a conflict file
                if is_conflict_file(&path_str, &state.config.syncthing.conflict_pattern) {
                    if let Some(original) = find_original_file(&path_str) {
                        tracing::info!("Conflict detected: {} -> {}", original, path_str);

                        state
                            .add_conflict(ConflictInfo {
                                original_path: original.clone(),
                                conflict_path: path_str.clone(),
                                detected_at: Utc::now(),
                            })
                            .await;

                        state.send_event(FileEvent::ConflictDetected {
                            original,
                            conflict: path_str,
                        });
                    }
                } else {
                    // Regular KDBX file
                    if let Ok(metadata) = tokio::fs::metadata(&path).await {
                        let info = KdbxFileInfo {
                            path: path_str.clone(),
                            name: path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default(),
                            size: metadata.len(),
                            modified: metadata
                                .modified()
                                .ok()
                                .map(chrono::DateTime::from)
                                .unwrap_or_else(Utc::now),
                        };

                        state.add_kdbx_file(info).await;
                        state.send_event(FileEvent::FileChanged { path: path_str });
                    }
                }
            }
            EventKind::Remove(_) => {
                if is_conflict_file(&path_str, &state.config.syncthing.conflict_pattern) {
                    state.remove_conflict(&path_str).await;
                } else {
                    state.remove_kdbx_file(&path_str).await;
                }
                state.send_event(FileEvent::FileDeleted { path: path_str });
            }
            _ => {}
        }
    }
}

/// Scan a directory for existing KDBX files
async fn scan_directory(
    state: &Arc<AppState>,
    dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut entries = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if path.is_dir() {
            Box::pin(scan_directory(state, &path)).await?;
        } else if path.extension().map(|e| e == "kdbx").unwrap_or(false) {
            let path_str = path.to_string_lossy().to_string();

            if is_conflict_file(&path_str, &state.config.syncthing.conflict_pattern) {
                if let Some(original) = find_original_file(&path_str) {
                    state
                        .add_conflict(ConflictInfo {
                            original_path: original,
                            conflict_path: path_str,
                            detected_at: Utc::now(),
                        })
                        .await;
                }
            } else if let Ok(metadata) = entry.metadata().await {
                let info = KdbxFileInfo {
                    path: path_str,
                    name: path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    size: metadata.len(),
                    modified: metadata
                        .modified()
                        .ok()
                        .map(chrono::DateTime::from)
                        .unwrap_or_else(Utc::now),
                };
                state.add_kdbx_file(info).await;
            }
        }
    }

    Ok(())
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
