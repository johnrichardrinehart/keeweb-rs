//! Application state management

use crate::worker_client::WorkerClient;
use keeweb_wasm::WasmDatabase;
use leptos::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;

// Thread-local worker client (WASM is single-threaded)
thread_local! {
    static WORKER_CLIENT: RefCell<Option<WorkerClient>> = const { RefCell::new(None) };
}

/// Get or initialize the worker client
fn get_worker_client() -> Result<(), String> {
    WORKER_CLIENT.with(|client| {
        let mut client = client.borrow_mut();
        if client.is_none() {
            log::debug!("Initializing worker client");
            match WorkerClient::new() {
                Ok(wc) => {
                    *client = Some(wc);
                    Ok(())
                }
                Err(e) => Err(format!("Failed to create worker: {:?}", e)),
            }
        } else {
            Ok(())
        }
    })
}

/// Send unlock request to worker
pub fn worker_unlock<F>(data: Vec<u8>, password: String, callback: F)
where
    F: FnOnce(Result<crate::worker_client::UnlockResult, String>) + 'static,
{
    if let Err(e) = get_worker_client() {
        callback(Err(e));
        return;
    }

    WORKER_CLIENT.with(|client| {
        if let Some(ref wc) = *client.borrow() {
            wc.unlock(data, password, callback);
        }
    });
}

/// Current view/screen of the application
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AppView {
    /// Initial file picker screen
    #[default]
    FilePicker,
    /// Password unlock dialog
    Unlock,
    /// Main database view
    Database,
}

/// Source of a database file
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseSource {
    /// Local file (drag-and-drop)
    Local { name: String },
    /// Google Drive
    GoogleDrive { file_id: String, name: String },
    /// Dropbox
    Dropbox { path: String, name: String },
    /// Box
    Box { file_id: String, name: String },
    /// Backend server
    Backend { path: String, name: String },
}

impl DatabaseSource {
    pub fn name(&self) -> &str {
        match self {
            Self::Local { name } => name,
            Self::GoogleDrive { name, .. } => name,
            Self::Dropbox { name, .. } => name,
            Self::Box { name, .. } => name,
            Self::Backend { name, .. } => name,
        }
    }
}

/// Entry data for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInfo {
    pub uuid: String,
    pub title: String,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    pub url: String,
    pub notes: String,
    #[serde(rename = "parent_group")]
    pub group_uuid: Option<String>,
}

/// Group data for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub uuid: String,
    pub name: String,
    pub parent: Option<String>,
    #[serde(rename = "icon_id")]
    pub icon: Option<u32>,
}

/// Global application state - all fields are Copy signals
#[derive(Clone, Copy)]
pub struct AppState {
    /// Current view
    pub current_view: RwSignal<AppView>,
    /// Currently open database (wrapped in Rc for Clone)
    pub database: RwSignal<Option<Rc<std::cell::RefCell<WasmDatabase>>>>,
    /// Database name
    pub database_name: RwSignal<String>,
    /// Source of the database
    pub database_source: RwSignal<Option<DatabaseSource>>,
    /// Pending file data awaiting password
    pub pending_file_data: RwSignal<Option<Vec<u8>>>,
    /// All entries in the database
    pub entries: RwSignal<Vec<EntryInfo>>,
    /// All groups in the database
    pub groups: RwSignal<Vec<GroupInfo>>,
    /// Currently selected group UUID
    pub selected_group: RwSignal<Option<String>>,
    /// Currently selected entry UUID
    pub selected_entry: RwSignal<Option<String>>,
    /// Search query
    pub search_query: RwSignal<String>,
    /// Error message to display
    pub error_message: RwSignal<Option<String>>,
    /// Backend URL (if configured)
    pub backend_url: RwSignal<Option<String>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            current_view: create_rw_signal(AppView::FilePicker),
            database: create_rw_signal(None),
            database_name: create_rw_signal(String::new()),
            database_source: create_rw_signal(None),
            pending_file_data: create_rw_signal(None),
            entries: create_rw_signal(Vec::new()),
            groups: create_rw_signal(Vec::new()),
            selected_group: create_rw_signal(None),
            selected_entry: create_rw_signal(None),
            search_query: create_rw_signal(String::new()),
            error_message: create_rw_signal(None),
            backend_url: create_rw_signal(None),
        }
    }

    /// Set pending file data and show unlock dialog
    pub fn set_pending_file(&self, data: Vec<u8>, source: DatabaseSource) {
        self.database_name.set(source.name().to_string());
        self.database_source.set(Some(source));
        self.pending_file_data.set(Some(data));
        self.current_view.set(AppView::Unlock);
    }

    /// Attempt to unlock the database with a password
    pub fn unlock_database(&self, password: &str) -> Result<(), String> {
        log::debug!("unlock_database called");

        // Use get_untracked since we're not in a reactive context
        let data = self
            .pending_file_data
            .get_untracked()
            .ok_or_else(|| "No file data pending".to_string())?;

        log::debug!("Got pending file data, {} bytes", data.len());
        log::debug!("Attempting to open database (this may take a while for Argon2 key derivation)...");

        match WasmDatabase::open(&data, password) {
            Ok(db) => {
                log::debug!("Database opened successfully");

                // Parse entries and groups
                let entries_json = db.get_entries();
                log::debug!("Entries JSON: {}", &entries_json[..entries_json.len().min(500)]);
                let entries: Vec<EntryInfo> =
                    serde_json::from_str(&entries_json).unwrap_or_default();

                let groups_json = db.get_groups();
                let groups: Vec<GroupInfo> = serde_json::from_str(&groups_json).unwrap_or_default();

                // Update state
                self.database
                    .set(Some(Rc::new(std::cell::RefCell::new(db))));
                self.entries.set(entries);
                self.groups.set(groups);
                self.pending_file_data.set(None);
                self.error_message.set(None);
                self.current_view.set(AppView::Database);

                log::info!("Database unlocked successfully");
                Ok(())
            }
            Err(e) => {
                // Convert JsValue error to string
                let error = e
                    .as_string()
                    .unwrap_or_else(|| format!("{:?}", e));
                log::error!("Failed to unlock database: {}", error);
                Err(error)
            }
        }
    }

    /// Attempt to unlock the database using Web Worker (non-blocking)
    /// This is preferred for databases with heavy KDF settings (high Argon2 memory/iterations)
    pub fn unlock_database_async(
        &self,
        password: &str,
        is_unlocking: RwSignal<bool>,
        error_signal: RwSignal<Option<String>>,
    ) {
        log::debug!("unlock_database_async called");

        // Use get_untracked since we're not in a reactive context
        let data = match self.pending_file_data.get_untracked() {
            Some(d) => d,
            None => {
                error_signal.set(Some("No file data pending".to_string()));
                is_unlocking.set(false);
                return;
            }
        };

        log::debug!("Got pending file data, {} bytes", data.len());
        log::debug!("Sending to worker for unlock (Argon2 will run in background)...");

        let state = *self;
        let password = password.to_string();

        worker_unlock(data, password, move |result| {
            // The callback runs outside Leptos context
            // Use wasm_bindgen_futures to schedule the update in a microtask
            // which will run in the proper context
            wasm_bindgen_futures::spawn_local(async move {
                match result {
                    Ok(unlock_result) => {
                        log::debug!("Worker unlock successful");

                        // Parse entries and groups from JSON
                        let entries: Vec<EntryInfo> =
                            serde_json::from_str(&unlock_result.entries_json).unwrap_or_default();
                        let groups: Vec<GroupInfo> =
                            serde_json::from_str(&unlock_result.groups_json).unwrap_or_default();

                        log::debug!("Parsed {} entries and {} groups", entries.len(), groups.len());

                        // Update state - spawn_local should provide proper context
                        state.database.set(None);
                        state.entries.set(entries);
                        state.groups.set(groups);
                        state.pending_file_data.set(None);
                        state.error_message.set(None);
                        state.current_view.set(AppView::Database);

                        log::info!("Database unlocked successfully via worker");
                    }
                    Err(e) => {
                        log::error!("Worker unlock failed: {}", e);
                        error_signal.set(Some(e));
                        is_unlocking.set(false);
                    }
                }
            });
        });
    }

    /// Close the current database
    pub fn close_database(&self) {
        self.database.set(None);
        self.database_name.set(String::new());
        self.database_source.set(None);
        self.entries.set(Vec::new());
        self.groups.set(Vec::new());
        self.selected_group.set(None);
        self.selected_entry.set(None);
        self.search_query.set(String::new());
        self.current_view.set(AppView::FilePicker);
    }

    /// Refresh entries from the database
    pub fn refresh_entries(&self) {
        if let Some(db) = self.database.get() {
            let db = db.borrow();
            let entries_json = db.get_entries();
            let entries: Vec<EntryInfo> = serde_json::from_str(&entries_json).unwrap_or_default();
            self.entries.set(entries);
        }
    }

    /// Get filtered entries based on search query and selected group
    pub fn filtered_entries(&self) -> Vec<EntryInfo> {
        let entries = self.entries.get();
        let query = self.search_query.get().to_lowercase();
        let selected_group = self.selected_group.get();

        entries
            .into_iter()
            .filter(|entry| {
                // Filter by group if selected
                if let Some(ref group_uuid) = selected_group {
                    if entry.group_uuid.as_ref() != Some(group_uuid) {
                        return false;
                    }
                }

                // Filter by search query
                if !query.is_empty() {
                    let title_match = entry.title.to_lowercase().contains(&query);
                    let username_match = entry.username.to_lowercase().contains(&query);
                    let url_match = entry.url.to_lowercase().contains(&query);
                    return title_match || username_match || url_match;
                }

                true
            })
            .collect()
    }

    /// Get the currently selected entry
    pub fn get_selected_entry(&self) -> Option<EntryInfo> {
        let selected_uuid = self.selected_entry.get()?;
        self.entries
            .get()
            .into_iter()
            .find(|e| e.uuid == selected_uuid)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
