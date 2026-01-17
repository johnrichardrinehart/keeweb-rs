//! Application state

use crate::config::Config;
use tokio::sync::broadcast;

/// File system event
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// A KDBX file was created or modified
    FileChanged { path: String },
    /// A KDBX file was deleted
    FileDeleted { path: String },
    /// A Syncthing conflict file was detected
    ConflictDetected { original: String, conflict: String },
}

/// Application state shared across handlers
pub struct AppState {
    pub config: Config,
    /// Broadcast channel for file events
    pub events_tx: broadcast::Sender<FileEvent>,
    /// Currently known KDBX files
    pub kdbx_files: tokio::sync::RwLock<Vec<KdbxFileInfo>>,
    /// Currently known conflict files
    pub conflicts: tokio::sync::RwLock<Vec<ConflictInfo>>,
}

/// Information about a KDBX file
#[derive(Debug, Clone, serde::Serialize)]
pub struct KdbxFileInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified: chrono::DateTime<chrono::Utc>,
}

/// Information about a conflict
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConflictInfo {
    pub original_path: String,
    pub conflict_path: String,
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let (events_tx, _) = broadcast::channel(100);

        Self {
            config,
            events_tx,
            kdbx_files: tokio::sync::RwLock::new(Vec::new()),
            conflicts: tokio::sync::RwLock::new(Vec::new()),
        }
    }

    /// Add or update a KDBX file
    pub async fn add_kdbx_file(&self, info: KdbxFileInfo) {
        let mut files = self.kdbx_files.write().await;
        if let Some(existing) = files.iter_mut().find(|f| f.path == info.path) {
            *existing = info;
        } else {
            files.push(info);
        }
    }

    /// Remove a KDBX file
    pub async fn remove_kdbx_file(&self, path: &str) {
        let mut files = self.kdbx_files.write().await;
        files.retain(|f| f.path != path);
    }

    /// Add a conflict
    pub async fn add_conflict(&self, info: ConflictInfo) {
        let mut conflicts = self.conflicts.write().await;
        if !conflicts
            .iter()
            .any(|c| c.conflict_path == info.conflict_path)
        {
            conflicts.push(info);
        }
    }

    /// Remove a conflict
    pub async fn remove_conflict(&self, conflict_path: &str) {
        let mut conflicts = self.conflicts.write().await;
        conflicts.retain(|c| c.conflict_path != conflict_path);
    }

    /// Send a file event
    pub fn send_event(&self, event: FileEvent) {
        let _ = self.events_tx.send(event);
    }
}
