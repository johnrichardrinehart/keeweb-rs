//! Application state management

use crate::argon2_client::Argon2Client;
use crate::helper_client;
use crate::worker_client::WorkerClient;
use keeweb_wasm::WasmDatabase;
use leptos::*;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen_futures::spawn_local;

/// Log timing information only in debug builds
#[cfg(debug_assertions)]
macro_rules! debug_timing {
    ($($arg:tt)*) => {
        log::info!($($arg)*)
    };
}

#[cfg(not(debug_assertions))]
macro_rules! debug_timing {
    ($($arg:tt)*) => {};
}

/// Get current performance timestamp
fn perf_now() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

// Thread-local clients (WASM is single-threaded)
thread_local! {
    static WORKER_CLIENT: RefCell<Option<WorkerClient>> = const { RefCell::new(None) };
    static ARGON2_CLIENT: RefCell<Option<Argon2Client>> = const { RefCell::new(None) };
    static ARGON2_READY: RefCell<bool> = const { RefCell::new(false) };
}

/// Get or initialize the worker client
fn get_worker_client() -> Result<(), String> {
    WORKER_CLIENT.with(|client| {
        let mut client = client.borrow_mut();
        if client.is_none() {
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

/// Get or initialize the argon2 client
fn get_argon2_client() -> Result<(), String> {
    ARGON2_CLIENT.with(|client| {
        let mut client = client.borrow_mut();
        if client.is_none() {
            match Argon2Client::new() {
                Ok(ac) => {
                    *client = Some(ac);
                    Ok(())
                }
                Err(e) => Err(format!("Failed to create argon2 client: {:?}", e)),
            }
        } else {
            Ok(())
        }
    })
}

/// Initialize argon2 worker (call once at startup)
pub fn init_argon2<F>(callback: F)
where
    F: FnOnce(Result<(), String>) + 'static,
{
    if let Err(e) = get_argon2_client() {
        callback(Err(e));
        return;
    }

    ARGON2_CLIENT.with(|client| {
        if let Some(ref ac) = *client.borrow() {
            ac.init(move |result| {
                if result.is_ok() {
                    ARGON2_READY.with(|ready| *ready.borrow_mut() = true);
                }
                callback(result);
            });
        }
    });
}

/// Check if argon2 is ready
pub fn is_argon2_ready() -> bool {
    ARGON2_READY.with(|ready| *ready.borrow())
}


/// Run argon2 hash with parallel threads using argon2-pthread worker
pub fn argon2_hash<F>(
    argon2_type: String,
    password: Vec<u8>,
    salt: Vec<u8>,
    time_cost: u32,
    memory_cost: u32,
    threads: u32,
    hash_len: u32,
    callback: F,
) where
    F: FnOnce(Result<Vec<u8>, String>) + 'static,
{
    ARGON2_CLIENT.with(|client| {
        if let Some(ref ac) = *client.borrow() {
            ac.hash(
                &argon2_type,
                password,
                salt,
                time_cost,
                memory_cost,
                threads,
                hash_len,
                callback,
            );
        } else {
            callback(Err("Argon2 client not initialized".to_string()));
        }
    });
}

/// Send unlock request to worker (for decryption only, not KDF)
pub fn worker_decrypt<F>(data: Vec<u8>, password: String, derived_key: Vec<u8>, callback: F)
where
    F: FnOnce(Result<crate::worker_client::UnlockResult, String>) + 'static,
{
    if let Err(e) = get_worker_client() {
        callback(Err(e));
        return;
    }

    WORKER_CLIENT.with(|client| {
        if let Some(ref wc) = *client.borrow() {
            wc.decrypt_with_key(data, password, derived_key, callback);
        }
    });
}

/// Send unlock request to worker (uses fast parallel argon2)
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

/// Send unlock request to worker using SIMD-only argon2 (no pthreads)
/// Use this for high-memory databases (>=1GB) where pthread deadlocks
/// Faster than single-threaded rust-argon2 due to SIMD acceleration
#[allow(dead_code)]
pub fn worker_unlock_simd<F>(data: Vec<u8>, password: String, callback: F)
where
    F: FnOnce(Result<crate::worker_client::UnlockResult, String>) + 'static,
{
    if let Err(e) = get_worker_client() {
        callback(Err(e));
        return;
    }

    WORKER_CLIENT.with(|client| {
        if let Some(ref wc) = *client.borrow() {
            wc.unlock_simd(data, password, callback);
        }
    });
}

/// Send unlock request to worker using standard single-threaded Rust argon2
/// Slowest option, but most reliable fallback
pub fn worker_unlock_standard<F>(data: Vec<u8>, password: String, callback: F)
where
    F: FnOnce(Result<crate::worker_client::UnlockResult, String>) + 'static,
{
    if let Err(e) = get_worker_client() {
        callback(Err(e));
        return;
    }

    WORKER_CLIENT.with(|client| {
        if let Some(ref wc) = *client.borrow() {
            wc.unlock_standard(data, password, callback);
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

/// A historical version of an entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntryInfo {
    pub title: String,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    pub url: String,
    pub notes: String,
    /// Last modification time of this history version
    pub last_modification_time: Option<String>,
}

/// File attachment metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    /// Display name of the attachment
    pub name: String,
    /// Reference index to the binary data
    #[serde(rename = "ref")]
    pub ref_index: u32,
    /// Size in bytes (if known)
    #[serde(default)]
    pub size: Option<usize>,
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
    /// TOTP/OTP configuration (otpauth:// URI or bare secret)
    #[serde(default)]
    pub otp: Option<String>,
    /// Custom attributes (non-standard String fields)
    #[serde(default)]
    pub custom_attributes: std::collections::HashMap<String, String>,
    /// File attachments
    #[serde(default)]
    pub attachments: Vec<AttachmentInfo>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the entry expires
    #[serde(default)]
    pub expires: bool,
    /// Expiry time (if expires is true)
    pub expiry_time: Option<String>,
    /// Historical versions of this entry (oldest first)
    #[serde(default)]
    pub history: Vec<HistoryEntryInfo>,
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub fn unlock_database(&self, password: &str) -> Result<(), String> {
        let data = self
            .pending_file_data
            .get_untracked()
            .ok_or_else(|| "No file data pending".to_string())?;

        match WasmDatabase::open(&data, password) {
            Ok(db) => {
                let entries_json = db.get_entries();
                let entries: Vec<EntryInfo> =
                    serde_json::from_str(&entries_json).unwrap_or_default();

                let groups_json = db.get_groups();
                let groups: Vec<GroupInfo> = serde_json::from_str(&groups_json).unwrap_or_default();

                self.database
                    .set(Some(Rc::new(std::cell::RefCell::new(db))));
                self.entries.set(entries);
                self.groups.set(groups);
                self.pending_file_data.set(None);
                self.error_message.set(None);
                self.current_view.set(AppView::Database);

                Ok(())
            }
            Err(e) => {
                let error = e
                    .as_string()
                    .unwrap_or_else(|| format!("{:?}", e));
                Err(error)
            }
        }
    }

    /// Attempt to unlock the database using parallel Argon2 + Worker decryption
    /// This uses multi-threaded Argon2 via SharedArrayBuffer for best performance
    pub fn unlock_database_async(
        &self,
        password: &str,
        is_unlocking: RwSignal<bool>,
        error_signal: RwSignal<Option<String>>,
    ) {
        let data = match self.pending_file_data.get_untracked() {
            Some(d) => d,
            None => {
                error_signal.set(Some("No file data pending".to_string()));
                is_unlocking.set(false);
                return;
            }
        };

        let state = *self;
        let password_str = password.to_string();
        let data_clone = data.clone();

        // Step 1: Extract KDF parameters from KDBX header to check memory requirements
        let start_time = perf_now();
        log::info!("Extracting KDF params...");

        let kdf_params = match keeweb_wasm::get_kdf_params(&data, &password_str) {
            Ok(params) => {
                log::info!("KDF params extracted successfully");
                params
            }
            Err(e) => {
                let err = e.as_string().unwrap_or_else(|| format!("{:?}", e));
                log::error!("Failed to extract KDF params: {}", err);
                error_signal.set(Some(err));
                is_unlocking.set(false);
                return;
            }
        };

        let memory_mb = kdf_params.memory_kb() / 1024;
        let parallelism = kdf_params.parallelism();
        log::info!("KDF params: memory_kb={}, memory_mb={}, parallelism={}", kdf_params.memory_kb(), memory_mb, parallelism);

        // For high memory (>=256MB), try the helper server first for native speed.
        // The helper doesn't require pthread/SharedArrayBuffer - it runs natively on the server.
        // This check happens BEFORE checking is_argon2_ready() because the helper is preferred
        // for high-memory databases regardless of browser capabilities.
        // Default KeePassXC memory is 64MB, so this catches users with elevated security settings.
        if memory_mb >= 256 {
                let argon2_type = kdf_params.kdf_type();
                let composite_key = kdf_params.composite_key();
                let salt = kdf_params.salt();
                let iterations = kdf_params.iterations() as u32;
                let memory_kb = kdf_params.memory_kb() as u32;
                let version = kdf_params.version();

                // Try helper server first if configured
                let helper_configured = helper_client::is_helper_configured();
                log::info!("High memory ({}MB) database - helper configured: {}", memory_mb, helper_configured);

                if helper_configured {
                    let argon2_type_clone = argon2_type.clone();
                    let composite_key_clone = composite_key.clone();
                    let salt_clone = salt.clone();
                    let data_for_helper = data_clone.clone();
                    let password_for_helper = password_str.clone();

                    spawn_local(async move {
                        log::info!("Checking helper availability...");
                        match helper_client::check_helper_available().await {
                            Ok(true) => {
                                log::info!("Helper available, calling argon2_hash...");
                                match helper_client::helper_argon2_hash(
                                    &argon2_type_clone,
                                    &composite_key_clone,
                                    &salt_clone,
                                    iterations,
                                    memory_kb,
                                    parallelism,
                                    32,
                                    version,
                                )
                                .await
                                {
                                    Ok((derived_key, server_time_ms)) => {
                                        debug_timing!("[TIMING] Argon2 (helper server): {}ms", server_time_ms);
                                        let decrypt_start = perf_now();

                                        // Decrypt with the derived key
                                        worker_decrypt(
                                            data_for_helper,
                                            password_for_helper,
                                            derived_key,
                                            move |result| {
                                                spawn_local(async move {
                                                    match result {
                                                        Ok(unlock_result) => {
                                                            let decrypt_time = perf_now() - decrypt_start;
                                                            debug_timing!("[TIMING] Decryption: {:.0}ms", decrypt_time);

                                                            let entries: Vec<EntryInfo> =
                                                                serde_json::from_str(
                                                                    &unlock_result.entries_json,
                                                                )
                                                                .unwrap_or_default();
                                                            let groups: Vec<GroupInfo> =
                                                                serde_json::from_str(
                                                                    &unlock_result.groups_json,
                                                                )
                                                                .unwrap_or_default();

                                                            state.database.set(None);
                                                            state.entries.set(entries);
                                                            state.groups.set(groups);
                                                            state.pending_file_data.set(None);
                                                            state.error_message.set(None);
                                                            state.current_view.set(AppView::Database);

                                                            let total_time = perf_now() - start_time;
                                                            debug_timing!("[TIMING] Total unlock (helper): {:.0}ms", total_time);
                                                        }
                                                        Err(e) => {
                                                            error_signal.set(Some(e));
                                                            is_unlocking.set(false);
                                                        }
                                                    }
                                                });
                                            },
                                        );
                                    }
                                    Err(e) => {
                                        // Fall back to single-threaded
                                        log::warn!("Helper argon2 failed: {:?}, falling back to slow unlock", e);
                                        do_slow_unlock(
                                            data_for_helper,
                                            password_for_helper,
                                            state,
                                            start_time,
                                            error_signal,
                                            is_unlocking,
                                            memory_mb,
                                        );
                                    }
                                }
                            }
                            Ok(false) => {
                                log::info!("Helper not available (check returned false), falling back to slow unlock");
                                do_slow_unlock(
                                    data_for_helper,
                                    password_for_helper,
                                    state,
                                    start_time,
                                    error_signal,
                                    is_unlocking,
                                    memory_mb,
                                );
                            }
                            Err(e) => {
                                log::warn!("Helper check failed: {}, falling back to slow unlock", e);
                                do_slow_unlock(
                                    data_for_helper,
                                    password_for_helper,
                                    state,
                                    start_time,
                                    error_signal,
                                    is_unlocking,
                                    memory_mb,
                                );
                            }
                        }
                    });
                    return;
                }

                // No helper configured, use slow fallback
                log::info!("No helper configured, using slow fallback");
                do_slow_unlock(
                    data_clone,
                    password_str.clone(),
                    state,
                    start_time,
                    error_signal,
                    is_unlocking,
                    memory_mb,
                );
                return;
        }

        // For normal memory (<1GB), use parallel argon2 if available
        let argon2_ready = is_argon2_ready();
        log::info!("Normal memory path: is_argon2_ready() = {}", argon2_ready);

        if argon2_ready {
            // Step 2: Run Argon2 with parallel threads
            let argon2_type = kdf_params.kdf_type();
            let composite_key = kdf_params.composite_key();
            let salt = kdf_params.salt();
            let iterations = kdf_params.iterations() as u32;
            let memory_kb = kdf_params.memory_kb() as u32;

            argon2_hash(
                argon2_type,
                composite_key,
                salt,
                iterations,
                memory_kb,
                parallelism,
                32,
                move |argon2_result| {
                    wasm_bindgen_futures::spawn_local(async move {
                        match argon2_result {
                            Ok(derived_key) => {
                                let argon2_time = perf_now() - start_time;
                                debug_timing!("[TIMING] Argon2 (parallel): {:.0}ms", argon2_time);
                                let decrypt_start = perf_now();

                                // Step 3: Decrypt with the derived key in worker
                                worker_decrypt(data_clone, password_str, derived_key, move |result| {
                                    wasm_bindgen_futures::spawn_local(async move {
                                        match result {
                                            Ok(unlock_result) => {
                                                let decrypt_time = perf_now() - decrypt_start;
                                                debug_timing!("[TIMING] Decryption: {:.0}ms", decrypt_time);

                                                let entries: Vec<EntryInfo> =
                                                    serde_json::from_str(&unlock_result.entries_json).unwrap_or_default();
                                                let groups: Vec<GroupInfo> =
                                                    serde_json::from_str(&unlock_result.groups_json).unwrap_or_default();

                                                state.database.set(None);
                                                state.entries.set(entries);
                                                state.groups.set(groups);
                                                state.pending_file_data.set(None);
                                                state.error_message.set(None);
                                                state.current_view.set(AppView::Database);

                                                let total_time = perf_now() - start_time;
                                                debug_timing!("[TIMING] Total unlock (parallel): {:.0}ms", total_time);
                                            }
                                            Err(e) => {
                                                error_signal.set(Some(e));
                                                is_unlocking.set(false);
                                            }
                                        }
                                    });
                                });
                            }
                            Err(_) => {
                                // Fall back to worker-based unlock
                                worker_unlock(data_clone, password_str, move |result| {
                                    wasm_bindgen_futures::spawn_local(async move {
                                        match result {
                                            Ok(unlock_result) => {
                                                let total_time = perf_now() - start_time;
                                                debug_timing!("[TIMING] Total unlock (worker fallback): {:.0}ms", total_time);

                                                let entries: Vec<EntryInfo> =
                                                    serde_json::from_str(&unlock_result.entries_json).unwrap_or_default();
                                                let groups: Vec<GroupInfo> =
                                                    serde_json::from_str(&unlock_result.groups_json).unwrap_or_default();

                                                state.database.set(None);
                                                state.entries.set(entries);
                                                state.groups.set(groups);
                                                state.pending_file_data.set(None);
                                                state.error_message.set(None);
                                                state.current_view.set(AppView::Database);
                                            }
                                            Err(e) => {
                                                error_signal.set(Some(e));
                                                is_unlocking.set(false);
                                            }
                                        }
                                    });
                                });
                            }
                        }
                    });
                },
            );
        } else {
            // Argon2 not ready, use legacy worker unlock
            let start_time = perf_now();
            worker_unlock(data, password_str, move |result| {
                wasm_bindgen_futures::spawn_local(async move {
                    match result {
                        Ok(unlock_result) => {
                            let total_time = perf_now() - start_time;
                            debug_timing!("[TIMING] Total unlock (legacy worker): {:.0}ms", total_time);

                            let entries: Vec<EntryInfo> =
                                serde_json::from_str(&unlock_result.entries_json).unwrap_or_default();
                            let groups: Vec<GroupInfo> =
                                serde_json::from_str(&unlock_result.groups_json).unwrap_or_default();

                            state.database.set(None);
                            state.entries.set(entries);
                            state.groups.set(groups);
                            state.pending_file_data.set(None);
                            state.error_message.set(None);
                            state.current_view.set(AppView::Database);
                        }
                        Err(e) => {
                            error_signal.set(Some(e));
                            is_unlocking.set(false);
                        }
                    }
                });
            });
        }
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
    #[allow(dead_code)]
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

        let mut filtered: Vec<EntryInfo> = entries
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
            .collect();

        // Sort alphabetically by title (case-insensitive)
        filtered.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));

        filtered
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

/// Helper function for slow single-threaded unlock (used for high-memory Argon2)
fn do_slow_unlock(
    data: Vec<u8>,
    password: String,
    state: AppState,
    start_time: f64,
    error_signal: RwSignal<Option<String>>,
    is_unlocking: RwSignal<bool>,
    _memory_mb: u64,
) {
    worker_unlock_standard(data, password, move |result| {
        spawn_local(async move {
            match result {
                Ok(unlock_result) => {
                    let total_time = perf_now() - start_time;
                    debug_timing!("[TIMING] Total unlock (slow/single-threaded): {:.0}ms", total_time);

                    let entries: Vec<EntryInfo> =
                        serde_json::from_str(&unlock_result.entries_json).unwrap_or_default();
                    let groups: Vec<GroupInfo> =
                        serde_json::from_str(&unlock_result.groups_json).unwrap_or_default();

                    state.database.set(None);
                    state.entries.set(entries);
                    state.groups.set(groups);
                    state.pending_file_data.set(None);
                    state.error_message.set(None);
                    state.current_view.set(AppView::Database);
                }
                Err(e) => {
                    error_signal.set(Some(e));
                    is_unlocking.set(false);
                }
            }
        });
    });
}
