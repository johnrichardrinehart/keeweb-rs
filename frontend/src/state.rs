//! Application state management

use crate::kdf;
use crate::server::{self, ReplaceError};
use crate::utils::files;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use keeweb_wasm::WasmDocument;
use keeweb_wasm::document::{Change, ChangeOutcome, EntryView, GroupView, MetaView};
use leptos::*;
use std::rc::Rc;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use zeroize::Zeroizing;

/// How many times a save merges with a newer server revision before giving up.
const MAX_MERGE_ATTEMPTS: usize = 3;

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

/// Theme preference (2-state: light or dark)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    /// Light mode
    Light,
    /// Dark mode
    Dark,
}

impl Default for Theme {
    fn default() -> Self {
        // Default to system preference
        if system_prefers_dark() {
            Theme::Dark
        } else {
            Theme::Light
        }
    }
}

const THEME_STORAGE_KEY: &str = "keeweb-rs-theme";

/// Load theme preference from localStorage
fn load_theme_preference() -> Theme {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return Theme::default(),
    };

    let storage = match window.local_storage() {
        Ok(Some(s)) => s,
        _ => return Theme::default(),
    };

    match storage.get_item(THEME_STORAGE_KEY) {
        Ok(Some(value)) => match value.as_str() {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            // Legacy "system" or unknown values: use system preference
            _ => Theme::default(),
        },
        _ => Theme::default(),
    }
}

/// Save theme preference to localStorage
fn save_theme_preference(theme: Theme) {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return,
    };

    let storage = match window.local_storage() {
        Ok(Some(s)) => s,
        _ => return,
    };

    let value = match theme {
        Theme::Light => "light",
        Theme::Dark => "dark",
    };

    let _ = storage.set_item(THEME_STORAGE_KEY, value);
}

/// Check if system prefers dark mode
fn system_prefers_dark() -> bool {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return true, // Default to dark if can't detect
    };

    window
        .match_media("(prefers-color-scheme: dark)")
        .ok()
        .flatten()
        .map(|mq| mq.matches())
        .unwrap_or(true)
}

/// Apply theme to the document
pub fn apply_theme(theme: Theme) {
    let window = match web_sys::window() {
        Some(w) => w,
        None => return,
    };

    let document = match window.document() {
        Some(d) => d,
        None => return,
    };

    let html = match document.document_element() {
        Some(e) => e,
        None => return,
    };

    // Set data-theme attribute on <html> element
    let theme_value = match theme {
        Theme::Dark => "dark",
        Theme::Light => "light",
    };
    let _ = html.set_attribute("data-theme", theme_value);
}

/// Initialize theme on app startup
pub fn init_theme(theme: Theme) {
    apply_theme(theme);
}

/// Where a vault came from and where saves go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseSource {
    /// Opened from disk in a build without server storage. Saving downloads a copy.
    Local { name: String },
    /// Stored on the keeweb-server. `revision` is the server revision of the bytes the
    /// session's merge base was read from.
    Server {
        id: String,
        name: String,
        revision: String,
    },
}

impl DatabaseSource {
    pub fn name(&self) -> &str {
        match self {
            Self::Local { name } | Self::Server { name, .. } => name,
        }
    }
}

/// An encrypted vault waiting for its password.
#[derive(Clone)]
pub struct PendingVault {
    pub data: Vec<u8>,
    pub source: DatabaseSource,
}

/// An unlocked vault.
struct Session {
    /// The document with all edits applied.
    local: WasmDocument,
    /// The document as last read from or written to the source; the merge base.
    base: WasmDocument,
    /// Encrypted bytes of `base`, to unlock again after locking.
    base_bytes: Vec<u8>,
    source: DatabaseSource,
}

/// Leaving the unlocked vault, which discards unsaved changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Departure {
    /// Close the vault and return to the vault picker.
    Close,
    /// Lock the vault and ask for its password again.
    Lock,
}

/// What the entry panel is editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryEditor {
    Edit(Uuid),
    Create { group: Uuid },
}

/// A custom icon ready for `<img src>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconImage {
    pub uuid: Uuid,
    pub url: String,
}

/// Connection state for the optional localhost unlock helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HelperStatus {
    #[default]
    Checking,
    Connected,
    Unavailable,
}

/// Result of the save state machine, applied to the session afterwards.
struct SaveProgress {
    local: WasmDocument,
    base: WasmDocument,
    base_bytes: Vec<u8>,
    source: DatabaseSource,
    merged: bool,
    conflicts: Vec<String>,
}

/// Global application state - all fields are Copy signals
#[derive(Clone, Copy)]
pub struct AppState {
    /// Current view
    pub current_view: RwSignal<AppView>,
    /// Database name
    pub database_name: RwSignal<String>,
    /// Vault awaiting its password
    pub pending: RwSignal<Option<PendingVault>>,
    session: StoredValue<Option<Session>>,
    /// All entries in the database, including the recycle bin
    pub entries: RwSignal<Rc<Vec<EntryView>>>,
    /// All groups in the database, root first
    pub groups: RwSignal<Rc<Vec<GroupView>>>,
    /// Database settings
    pub meta: RwSignal<Option<MetaView>>,
    /// Custom icons in document order
    pub custom_icons: RwSignal<Rc<Vec<IconImage>>>,
    /// Summaries of unsaved changes, oldest first
    pub changes: RwSignal<Vec<String>>,
    /// A save is running; edits are refused meanwhile
    pub saving: RwSignal<bool>,
    /// Short confirmation after a successful save
    pub save_notice: RwSignal<Option<String>>,
    /// Titles changed on both sides in the last merging save
    pub merge_conflicts: RwSignal<Vec<String>>,
    /// Departure waiting for the unsaved-changes decision
    pub departure: RwSignal<Option<Departure>>,
    /// Whether the unsaved-changes list is open
    pub show_changes: RwSignal<bool>,
    /// Whether the database settings dialog is open
    pub show_settings: RwSignal<bool>,
    /// Entry editor shown in the detail panel
    pub editor: RwSignal<Option<EntryEditor>>,
    /// Currently selected group UUID
    pub selected_group: RwSignal<Option<Uuid>>,
    /// Currently selected tag
    pub selected_tag: RwSignal<Option<String>>,
    /// Currently selected entry UUID
    pub selected_entry: RwSignal<Option<Uuid>>,
    /// Search query
    pub search_query: RwSignal<String>,
    /// Error message to display
    pub error_message: RwSignal<Option<String>>,
    /// Connection state for the localhost native unlock helper
    pub helper_status: RwSignal<HelperStatus>,
    /// Backend URL (if configured)
    #[allow(dead_code)]
    pub backend_url: RwSignal<Option<String>>,
    /// Theme preference
    pub theme: RwSignal<Theme>,
}

impl AppState {
    pub fn new() -> Self {
        // Load theme preference from localStorage
        let initial_theme = load_theme_preference();

        Self {
            current_view: create_rw_signal(AppView::FilePicker),
            database_name: create_rw_signal(String::new()),
            pending: create_rw_signal(None),
            session: store_value(None),
            entries: create_rw_signal(Rc::new(Vec::new())),
            groups: create_rw_signal(Rc::new(Vec::new())),
            meta: create_rw_signal(None),
            custom_icons: create_rw_signal(Rc::new(Vec::new())),
            changes: create_rw_signal(Vec::new()),
            saving: create_rw_signal(false),
            save_notice: create_rw_signal(None),
            merge_conflicts: create_rw_signal(Vec::new()),
            departure: create_rw_signal(None),
            show_changes: create_rw_signal(false),
            show_settings: create_rw_signal(false),
            editor: create_rw_signal(None),
            selected_group: create_rw_signal(None),
            selected_tag: create_rw_signal(None),
            selected_entry: create_rw_signal(None),
            search_query: create_rw_signal(String::new()),
            error_message: create_rw_signal(None),
            helper_status: create_rw_signal(HelperStatus::Checking),
            backend_url: create_rw_signal(None),
            theme: create_rw_signal(initial_theme),
        }
    }

    /// Set the theme and persist to localStorage
    pub fn set_theme(&self, theme: Theme) {
        self.theme.set(theme);
        save_theme_preference(theme);
        apply_theme(theme);
    }

    /// Toggle between light and dark themes
    pub fn cycle_theme(&self) {
        let next = match self.theme.get() {
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Light,
        };
        self.set_theme(next);
    }

    /// Set pending file data and show unlock dialog
    pub fn set_pending_file(&self, data: Vec<u8>, source: DatabaseSource) {
        self.database_name.set(source.name().to_string());
        self.pending.set(Some(PendingVault { data, source }));
        self.current_view.set(AppView::Unlock);
    }

    /// Derive the transformed key with the fastest available Argon2, then open the
    /// document on the main thread.
    pub fn unlock(
        &self,
        password: Zeroizing<String>,
        is_unlocking: RwSignal<bool>,
        error_signal: RwSignal<Option<String>>,
    ) {
        let fail = move |message: String| {
            error_signal.set(Some(message));
            is_unlocking.set(false);
        };
        let Some(PendingVault { data, source }) = self.pending.get_untracked() else {
            fail("No file data pending".to_string());
            return;
        };
        let params = match WasmDocument::kdf_params(&data) {
            Ok(params) => params,
            Err(error) => {
                fail(error);
                return;
            }
        };
        let composite_key = keeweb_wasm::composite_key(&password);
        drop(password);

        let state = *self;
        spawn_local(async move {
            let opened = match kdf::derive_transformed_key(&params, &composite_key).await {
                Ok(transformed_key) => WasmDocument::open(&data, &composite_key, &transformed_key),
                Err(error) => Err(error),
            };
            match opened {
                Ok(document) => state.open_session(document, data, source),
                Err(error) => fail(error),
            }
        });
    }

    fn open_session(&self, document: WasmDocument, data: Vec<u8>, source: DatabaseSource) {
        self.database_name.set(source.name().to_string());
        self.session.set_value(Some(Session {
            base: document.clone(),
            local: document,
            base_bytes: data,
            source,
        }));
        self.pending.set(None);
        self.changes.set(Vec::new());
        self.merge_conflicts.set(Vec::new());
        self.save_notice.set(None);
        self.error_message.set(None);
        self.refresh_views();
        self.current_view.set(AppView::Database);
    }

    /// Rebuild the reactive views from the local document.
    fn refresh_views(&self) {
        let views = self.session.with_value(|session| {
            session.as_ref().map(|session| {
                let document = session.local.document();
                let icons: Vec<IconImage> = document
                    .custom_icons()
                    .into_iter()
                    .map(|icon| IconImage {
                        uuid: icon.uuid,
                        url: format!("data:image/png;base64,{}", BASE64.encode(&icon.png)),
                    })
                    .collect();
                (
                    document.entries(),
                    document.groups(),
                    document.meta(),
                    icons,
                )
            })
        });
        let Some((entries, groups, meta, icons)) = views else {
            return;
        };

        // Drop selections that no longer exist (deleted, emptied, merged away).
        if let Some(selected) = self.selected_entry.get_untracked() {
            if !entries.iter().any(|entry| entry.uuid == selected) {
                self.selected_entry.set(None);
            }
        }
        if let Some(EntryEditor::Edit(uuid)) = self.editor.get_untracked() {
            if !entries.iter().any(|entry| entry.uuid == uuid) {
                self.editor.set(None);
            }
        }
        if let Some(selected) = self.selected_group.get_untracked() {
            if !groups.iter().any(|group| group.uuid == selected) {
                self.selected_group.set(None);
            }
        }

        self.entries.set(Rc::new(entries));
        self.groups.set(Rc::new(groups));
        self.meta.set(Some(meta));
        if self
            .custom_icons
            .with_untracked(|current| **current != icons)
        {
            self.custom_icons.set(Rc::new(icons));
        }
    }

    fn clear_session(&self) {
        self.session.set_value(None);
        self.entries.set(Rc::new(Vec::new()));
        self.groups.set(Rc::new(Vec::new()));
        self.meta.set(None);
        self.custom_icons.set(Rc::new(Vec::new()));
        self.changes.set(Vec::new());
        self.merge_conflicts.set(Vec::new());
        self.save_notice.set(None);
        self.departure.set(None);
        self.show_changes.set(false);
        self.show_settings.set(false);
        self.editor.set(None);
        self.selected_group.set(None);
        self.selected_tag.set(None);
        self.selected_entry.set(None);
        self.search_query.set(String::new());
    }

    /// Apply an edit to the local document and record it as unsaved.
    pub fn apply(&self, change: Change) -> Result<ChangeOutcome, String> {
        if self.saving.get_untracked() {
            return Err("Wait for the current save to finish.".to_string());
        }
        let outcome = self
            .session
            .try_update_value(|session| match session {
                Some(session) => session.local.apply(change),
                None => Err("No database is open.".to_string()),
            })
            .unwrap_or_else(|| Err("No database is open.".to_string()))?;
        if outcome.changed {
            self.changes
                .update(|changes| changes.push(outcome.summary.clone()));
            self.save_notice.set(None);
            self.refresh_views();
        }
        Ok(outcome)
    }

    /// [`AppState::apply`] for buttons without their own error display.
    pub fn apply_or_report(&self, change: Change) -> Option<ChangeOutcome> {
        match self.apply(change) {
            Ok(outcome) => {
                self.error_message.set(None);
                Some(outcome)
            }
            Err(error) => {
                self.error_message.set(Some(error));
                None
            }
        }
    }

    pub fn attachment(&self, entry: Uuid, name: &str) -> Option<Vec<u8>> {
        self.session.with_value(|session| {
            session
                .as_ref()
                .and_then(|session| session.local.document().attachment(entry, name))
        })
    }

    pub fn history_attachment(&self, entry: Uuid, index: usize, name: &str) -> Option<Vec<u8>> {
        self.session.with_value(|session| {
            session.as_ref().and_then(|session| {
                session
                    .local
                    .document()
                    .history_attachment(entry, index, name)
            })
        })
    }

    /// Whether there are unsaved changes (tracked).
    pub fn is_dirty(&self) -> bool {
        self.changes.with(|changes| !changes.is_empty())
    }

    pub fn root_group(&self) -> Option<Uuid> {
        self.groups
            .with(|groups| groups.first().map(|group| group.uuid))
    }

    pub fn group(&self, uuid: Uuid) -> Option<GroupView> {
        self.groups
            .with(|groups| groups.iter().find(|group| group.uuid == uuid).cloned())
    }

    pub fn entry(&self, uuid: Uuid) -> Option<EntryView> {
        self.entries
            .with(|entries| entries.iter().find(|entry| entry.uuid == uuid).cloned())
    }

    /// Group that new entries and groups go into: the selected group unless it is in
    /// the recycle bin, otherwise the root.
    pub fn target_group(&self) -> Option<Uuid> {
        self.selected_group
            .get_untracked()
            .and_then(|uuid| self.group(uuid))
            .filter(|group| !group.in_recycle_bin && !group.is_recycle_bin)
            .map(|group| group.uuid)
            .or_else(|| self.root_group())
    }

    /// Get filtered entries based on search query, selected group, or selected tag.
    /// Entries in the recycle bin only show while a recycle bin group is selected.
    pub fn filtered_entries(&self) -> Vec<EntryView> {
        let query = self.search_query.get().to_lowercase();
        let selected_group = self.selected_group.get();
        let selected_tag = self.selected_tag.get();
        let bin_selected = selected_group
            .and_then(|uuid| self.group(uuid))
            .is_some_and(|group| group.is_recycle_bin || group.in_recycle_bin);

        let mut filtered: Vec<EntryView> = self.entries.with(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    if let Some(tag) = &selected_tag {
                        if !entry.tags.contains(tag) {
                            return false;
                        }
                    } else if let Some(group) = selected_group {
                        if entry.group != group {
                            return false;
                        }
                    }
                    if entry.in_recycle_bin && !bin_selected {
                        return false;
                    }
                    if !query.is_empty() {
                        let matches = |key: &str| {
                            entry
                                .field(key)
                                .is_some_and(|value| value.to_lowercase().contains(&query))
                        };
                        return matches("Title") || matches("UserName") || matches("URL");
                    }
                    true
                })
                .cloned()
                .collect()
        });

        filtered.sort_by_cached_key(|entry| entry.title().to_lowercase());
        filtered
    }

    /// Get the currently selected entry
    pub fn get_selected_entry(&self) -> Option<EntryView> {
        let selected = self.selected_entry.get()?;
        self.entries
            .with(|entries| entries.iter().find(|entry| entry.uuid == selected).cloned())
    }

    /// Save to the vault's source. For server vaults a stale revision triggers a
    /// three-way merge with the server copy, up to [`MAX_MERGE_ATTEMPTS`] times.
    pub async fn save(self) -> Result<(), String> {
        if self.saving.get_untracked() {
            return Err("A save is already in progress.".to_string());
        }
        let snapshot = self.session.with_value(|session| {
            session.as_ref().map(|session| SaveProgress {
                local: session.local.clone(),
                base: session.base.clone(),
                base_bytes: Vec::new(),
                source: session.source.clone(),
                merged: false,
                conflicts: Vec::new(),
            })
        });
        let Some(mut progress) = snapshot else {
            return Err("No database is open.".to_string());
        };

        self.saving.set(true);
        self.save_notice.set(None);
        let result = match progress.source.clone() {
            DatabaseSource::Local { name } => save_local(&mut progress, &name),
            DatabaseSource::Server { id, name, .. } => save_server(&mut progress, &id, &name).await,
        };
        self.saving.set(false);

        if result.is_err() && !progress.merged {
            return result;
        }
        // Edits are refused while saving, so the session's local document is the one
        // this save started from and may be replaced by the merged result.
        let merged = progress.merged;
        self.session.update_value(|session| {
            if let Some(session) = session {
                session.local = progress.local;
                session.source = progress.source;
                if !progress.base_bytes.is_empty() {
                    session.base = progress.base;
                    session.base_bytes = progress.base_bytes;
                }
            }
        });
        if merged {
            self.refresh_views();
        }
        if result.is_ok() {
            self.changes.set(Vec::new());
            self.save_notice.set(Some(
                if merged {
                    "Saved with changes from the server"
                } else {
                    "Saved"
                }
                .to_string(),
            ));
            self.merge_conflicts.set(progress.conflicts);
        }
        result
    }

    /// Save from a button or shortcut; failures go to the error banner.
    pub fn save_in_background(&self) {
        let state = *self;
        spawn_local(async move {
            match state.save().await {
                Ok(()) => state.error_message.set(None),
                Err(error) => state
                    .error_message
                    .set(Some(format!("Save failed: {error}"))),
            }
        });
    }

    /// Leave the vault, asking first when there are unsaved changes.
    pub fn request_departure(&self, departure: Departure) {
        if self.changes.with_untracked(|changes| changes.is_empty()) {
            self.depart(departure);
        } else {
            self.departure.set(Some(departure));
        }
    }

    /// Leave the vault, discarding unsaved changes.
    pub fn depart(&self, departure: Departure) {
        match departure {
            Departure::Close => self.close_database(),
            Departure::Lock => self.lock(),
        }
    }

    /// Close the current database
    pub fn close_database(&self) {
        self.clear_session();
        self.pending.set(None);
        self.database_name.set(String::new());
        self.current_view.set(AppView::FilePicker);
    }

    /// Forget the decrypted document and ask for the password of the last saved
    /// version again.
    pub fn lock(&self) {
        let pending = self.session.with_value(|session| {
            session.as_ref().map(|session| PendingVault {
                data: session.base_bytes.clone(),
                source: session.source.clone(),
            })
        });
        self.clear_session();
        match pending {
            Some(pending) => {
                self.pending.set(Some(pending));
                self.current_view.set(AppView::Unlock);
            }
            None => self.close_database(),
        }
    }

    /// Lock after inactivity. Unsaved changes are saved first; if that fails the vault
    /// stays unlocked and shows why.
    pub async fn auto_lock(self) {
        if self.current_view.get_untracked() != AppView::Database {
            return;
        }
        if !self.changes.with_untracked(|changes| changes.is_empty()) {
            if let Err(error) = self.save().await {
                self.error_message.set(Some(format!(
                    "Auto-lock was cancelled because saving failed: {error}"
                )));
                return;
            }
        }
        self.departure.set(None);
        self.lock();
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Without server storage a save hands the encrypted file to the browser's downloads.
fn save_local(progress: &mut SaveProgress, name: &str) -> Result<(), String> {
    let bytes = progress.local.save()?;
    files::download_bytes(name, &bytes)?;
    progress.base = progress.local.clone();
    progress.base_bytes = bytes;
    Ok(())
}

async fn save_server(progress: &mut SaveProgress, id: &str, name: &str) -> Result<(), String> {
    let mut merges = 0;
    loop {
        let DatabaseSource::Server { revision, .. } = &progress.source else {
            return Err("The vault is not stored on the server.".to_string());
        };
        let bytes = progress.local.save()?;
        match server::replace(id, revision, &bytes).await {
            Ok(written) => {
                progress.source = DatabaseSource::Server {
                    id: written.id,
                    name: written.name,
                    revision: written.revision,
                };
                progress.base = progress.local.clone();
                progress.base_bytes = bytes;
                return Ok(());
            }
            Err(ReplaceError::Failed(error)) => return Err(error),
            Err(ReplaceError::Stale) if merges == MAX_MERGE_ATTEMPTS => {
                return Err(
                    "The database kept changing on the server. Try saving again.".to_string(),
                );
            }
            Err(ReplaceError::Stale) => {
                merges += 1;
                merge_server_revision(progress, id, name).await?;
            }
        }
    }
}

/// Merge the current server copy into the local document. Afterwards the server copy
/// is the merge base, since it is the common ancestor of the merged document and any
/// later server revision.
async fn merge_server_revision(
    progress: &mut SaveProgress,
    id: &str,
    name: &str,
) -> Result<(), String> {
    let (remote_bytes, remote_revision) = server::download(id, name).await?;
    // The server copy may have been re-salted by another client, so derive its key from
    // its own header with this session's password.
    let params = WasmDocument::kdf_params(&remote_bytes)?;
    let transformed_key =
        kdf::derive_transformed_key(&params, progress.local.composite_key()).await?;
    let remote = progress
        .local
        .open_revision(&remote_bytes, &transformed_key)
        .map_err(|error| format!("The server copy could not be opened: {error}"))?;
    let conflicts = progress.local.merge(&progress.base, &remote)?;
    for title in conflicts {
        if !progress.conflicts.contains(&title) {
            progress.conflicts.push(title);
        }
    }
    progress.base = remote;
    progress.base_bytes = remote_bytes;
    progress.source = DatabaseSource::Server {
        id: id.to_string(),
        name: name.to_string(),
        revision: remote_revision,
    };
    progress.merged = true;
    Ok(())
}
