//! Application state management
//!
//! Every unlocked vault is a [`Session`] in an ordered list shown as tabs. The signals on
//! [`AppState`] hold the view state (unsaved changes, selection, notices) of the vault on
//! screen only: switching parks them in the outgoing session and restores the incoming
//! session's, so components always read the active vault.

use crate::kdf;
use crate::quick_unlock::{self, UnlockError};
use crate::server::{self, ReplaceError};
use crate::utils::files;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use keeweb_wasm::WasmDocument;
use keeweb_wasm::document::{Change, ChangeOutcome, EntryView, GroupView, MetaView};
use leptos::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;
use zeroize::Zeroizing;

/// How many times a save merges with a newer server revision before giving up.
const MAX_MERGE_ATTEMPTS: usize = 3;

/// Which screen is showing, see [`AppState::view`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppView {
    /// Vault picker
    FilePicker,
    /// Unlock dialog over the vault picker
    Unlock,
    /// The active vault
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

const KEY_FILE_HINT_PREFIX: &str = "keeweb-rs-key-file:";

pub(crate) fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// Name of the key file last used to unlock `vault` on this device. Only the name is
/// remembered, never the contents.
pub fn key_file_hint(vault: &str) -> Option<String> {
    local_storage()?
        .get_item(&format!("{KEY_FILE_HINT_PREFIX}{vault}"))
        .ok()
        .flatten()
}

fn remember_key_file(vault: &str, name: Option<&str>) {
    let Some(storage) = local_storage() else {
        return;
    };
    let key = format!("{KEY_FILE_HINT_PREFIX}{vault}");
    let _ = match name {
        Some(name) => storage.set_item(&key, name),
        None => storage.remove_item(&key),
    };
}

const IDLE_LOCK_KEY: &str = "keeweb-rs-idle-lock-seconds";

/// Seconds of inactivity before every vault locks, on this browser.
pub const DEFAULT_IDLE_LOCK_SECONDS: u32 = 30;

/// Inactivity time before auto-lock on this browser; `None` turns auto-lock off.
pub fn load_idle_lock() -> Option<u32> {
    match local_storage().and_then(|s| s.get_item(IDLE_LOCK_KEY).ok().flatten()) {
        Some(value) if value == "never" => None,
        Some(value) => Some(value.parse().unwrap_or(DEFAULT_IDLE_LOCK_SECONDS)),
        None => Some(DEFAULT_IDLE_LOCK_SECONDS),
    }
}

pub fn save_idle_lock(seconds: Option<u32>) {
    if let Some(storage) = local_storage() {
        let value = seconds.map_or_else(|| "never".to_string(), |s| s.to_string());
        let _ = storage.set_item(IDLE_LOCK_KEY, &value);
    }
}

const PANE_WIDTHS_PREFIX: &str = "keeweb-rs-layout:";

/// Column widths in CSS pixels chosen on this browser for one vault; `None` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneWidths {
    pub sidebar: Option<i32>,
    pub list: Option<i32>,
}

pub fn load_pane_widths(vault: &str) -> PaneWidths {
    local_storage()
        .and_then(|s| {
            s.get_item(&format!("{PANE_WIDTHS_PREFIX}{vault}"))
                .ok()
                .flatten()
        })
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub fn save_pane_widths(vault: &str, widths: PaneWidths) {
    let Some(storage) = local_storage() else {
        return;
    };
    let key = format!("{PANE_WIDTHS_PREFIX}{vault}");
    if widths == PaneWidths::default() {
        let _ = storage.remove_item(&key);
    } else if let Ok(json) = serde_json::to_string(&widths) {
        let _ = storage.set_item(&key, &json);
    }
}

const TWO_COLUMN_KEY: &str = "keeweb-rs-two-column";

/// Whether wide entry panels show their fields in two columns on this browser.
pub fn load_two_column() -> bool {
    local_storage()
        .and_then(|s| s.get_item(TWO_COLUMN_KEY).ok().flatten())
        .is_none_or(|value| value != "false")
}

pub fn save_two_column(enabled: bool) {
    if let Some(storage) = local_storage() {
        let _ = storage.set_item(TWO_COLUMN_KEY, &enabled.to_string());
    }
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

    /// Identity of the vault on this device: the server id for server vaults, otherwise
    /// `local:` and the file name. Server ids are URL-safe base64 and contain no colon.
    pub fn vault_key(&self) -> String {
        match self {
            Self::Local { name } => format!("local:{name}"),
            Self::Server { id, .. } => id.clone(),
        }
    }
}

/// An encrypted vault waiting for its password.
#[derive(Clone)]
pub struct PendingVault {
    pub data: Vec<u8>,
    pub source: DatabaseSource,
}

/// A key file chosen in the unlock dialog, read locally and never uploaded.
#[derive(Clone)]
pub struct KeyFile {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
}

/// Identifies an unlocked vault for the lifetime of the page.
pub type SessionId = u64;

/// One tab of the vault tab strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTab {
    pub id: SessionId,
    pub name: String,
    pub dirty: bool,
}

/// View state of a vault while another vault or the picker is on screen.
#[derive(Default)]
struct ParkedView {
    changes: Vec<String>,
    save_notice: Option<String>,
    merge_conflicts: Vec<String>,
    error: Option<String>,
    editor: Option<EntryEditor>,
    selected_group: Option<Uuid>,
    selected_tag: Option<String>,
    selected_entry: Option<Uuid>,
    search_query: String,
}

/// An unlocked vault.
struct Session {
    id: SessionId,
    /// The document with all edits applied.
    local: WasmDocument,
    /// The document as last read from or written to the source; the merge base.
    base: WasmDocument,
    source: DatabaseSource,
    /// Argon2 salt in `local`'s header, which the session's transformed key belongs to.
    /// Saves and merges keep that header.
    kdf_salt: Vec<u8>,
    parked: ParkedView,
}

fn find_session(sessions: &[Session], id: SessionId) -> Option<&Session> {
    sessions.iter().find(|session| session.id == id)
}

fn find_session_mut(sessions: &mut [Session], id: SessionId) -> Option<&mut Session> {
    sessions.iter_mut().find(|session| session.id == id)
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
    source: DatabaseSource,
    merged: bool,
    conflicts: Vec<String>,
}

/// Global application state - all fields are Copy signals
#[derive(Clone, Copy)]
pub struct AppState {
    /// Unlocked vaults in tab order
    sessions: StoredValue<Vec<Session>>,
    next_session: StoredValue<SessionId>,
    /// Tab strip, in the order of `sessions`
    pub tabs: RwSignal<Vec<VaultTab>>,
    /// The vault on screen; `None` shows the vault picker
    pub active: RwSignal<Option<SessionId>>,
    /// Vault awaiting its password
    pub pending: RwSignal<Option<PendingVault>>,
    /// All entries in the active vault, including the recycle bin
    pub entries: RwSignal<Rc<Vec<EntryView>>>,
    /// All groups in the active vault, root first
    pub groups: RwSignal<Rc<Vec<GroupView>>>,
    /// Database settings
    pub meta: RwSignal<Option<MetaView>>,
    /// Custom icons in document order
    pub custom_icons: RwSignal<Rc<Vec<IconImage>>>,
    /// Summaries of unsaved changes, oldest first
    pub changes: RwSignal<Vec<String>>,
    /// A save is running; edits in every vault are refused meanwhile
    pub saving: RwSignal<bool>,
    /// Short confirmation after a successful save
    pub save_notice: RwSignal<Option<String>>,
    /// Titles changed on both sides in the last merging save
    pub merge_conflicts: RwSignal<Vec<String>>,
    /// Lock of the active vault waiting for the unsaved-changes decision
    pub lock_requested: RwSignal<bool>,
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
    /// Error of the active vault, or of the picker
    pub error_message: RwSignal<Option<String>>,
    /// Connection state for the localhost native unlock helper
    pub helper_status: RwSignal<HelperStatus>,
    /// Backend URL (if configured)
    #[allow(dead_code)]
    pub backend_url: RwSignal<Option<String>>,
    /// Theme preference
    pub theme: RwSignal<Theme>,
    /// Inactivity seconds before auto-lock on this browser; `None` turns it off.
    pub idle_lock: RwSignal<Option<u32>>,
    /// Column widths of the vault on screen, as stored on this browser
    pub pane_widths: RwSignal<PaneWidths>,
    /// Two-column entry panel on wide screens, on this browser
    pub two_column: RwSignal<bool>,
}

impl AppState {
    pub fn new() -> Self {
        // Load theme preference from localStorage
        let initial_theme = load_theme_preference();

        Self {
            sessions: store_value(Vec::new()),
            next_session: store_value(1),
            tabs: create_rw_signal(Vec::new()),
            active: create_rw_signal(None),
            pending: create_rw_signal(None),
            entries: create_rw_signal(Rc::new(Vec::new())),
            groups: create_rw_signal(Rc::new(Vec::new())),
            meta: create_rw_signal(None),
            custom_icons: create_rw_signal(Rc::new(Vec::new())),
            changes: create_rw_signal(Vec::new()),
            saving: create_rw_signal(false),
            save_notice: create_rw_signal(None),
            merge_conflicts: create_rw_signal(Vec::new()),
            lock_requested: create_rw_signal(false),
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
            idle_lock: create_rw_signal(load_idle_lock()),
            pane_widths: create_rw_signal(PaneWidths::default()),
            two_column: create_rw_signal(load_two_column()),
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

    /// The screen to show (tracked).
    pub fn view(&self) -> AppView {
        if self.active.with(Option::is_some) {
            AppView::Database
        } else if self.pending.with(Option::is_some) {
            AppView::Unlock
        } else {
            AppView::FilePicker
        }
    }

    /// File name of the vault on screen (tracked).
    pub fn active_name(&self) -> Option<String> {
        let active = self.active.get()?;
        self.tabs.with(|tabs| {
            tabs.iter()
                .find(|tab| tab.id == active)
                .map(|tab| tab.name.clone())
        })
    }

    /// Whether any unlocked vault has unsaved changes (tracked).
    pub fn any_dirty(&self) -> bool {
        self.tabs.with(|tabs| tabs.iter().any(|tab| tab.dirty))
    }

    /// Device identity of the vault on screen, see [`DatabaseSource::vault_key`].
    pub fn active_vault_key(&self) -> Option<String> {
        self.with_active(|session| session.source.vault_key())
    }

    fn with_active<O>(&self, f: impl FnOnce(&Session) -> O) -> Option<O> {
        let id = self.active.get_untracked()?;
        self.sessions
            .with_value(|sessions| find_session(sessions, id).map(f))
    }

    /// Ask for the password of an encrypted vault, or show it if it is already unlocked.
    pub fn set_pending_file(&self, data: Vec<u8>, source: DatabaseSource) {
        if self.switch_to_vault(&source.vault_key()) {
            return;
        }
        self.error_message.set(None);
        self.pending.set(Some(PendingVault { data, source }));
    }

    /// Shows the unlocked session of the vault with this [`DatabaseSource::vault_key`].
    /// Returns false when that vault is not unlocked.
    pub fn switch_to_vault(&self, vault: &str) -> bool {
        let id = self.sessions.with_value(|sessions| {
            sessions
                .iter()
                .find(|session| session.source.vault_key() == vault)
                .map(|session| session.id)
        });
        match id {
            Some(id) => {
                self.activate(id);
                true
            }
            None => false,
        }
    }

    /// Derive the transformed key with the fastest available Argon2, then open the
    /// document on the main thread. With `enroll_fingerprint` the session keys are then
    /// stored for fingerprint unlock on this device.
    pub fn unlock(
        &self,
        password: Zeroizing<String>,
        key_file: Option<KeyFile>,
        enroll_fingerprint: bool,
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
        // Next to a key file an empty password means the vault has no password part.
        let password = (!password.is_empty() || key_file.is_none()).then_some(password);
        let composite_key = match keeweb_wasm::composite_key(
            password.as_ref().map(|password| password.as_str()),
            key_file.as_ref().map(|file| file.data.as_slice()),
        ) {
            Ok(key) => key,
            Err(error) => {
                fail(error);
                return;
            }
        };
        drop(password);
        let key_file_name = key_file.map(|file| file.name);

        let state = *self;
        spawn_local(async move {
            let opened = match kdf::derive_transformed_key(&params, &composite_key).await {
                Ok(transformed_key) => WasmDocument::open(&data, &composite_key, &transformed_key),
                Err(error) => Err(error),
            };
            let document = match opened {
                Ok(document) => document,
                Err(error) => {
                    fail(error);
                    return;
                }
            };
            remember_key_file(&source.vault_key(), key_file_name.as_deref());
            let id = state.open_session(document, source, params.salt());
            if enroll_fingerprint {
                if let Err(error) = state.enroll_fingerprint(id).await {
                    state.set_error(
                        id,
                        Some(format!(
                            "Fingerprint unlock was not set up: {error} You can set it up later in Database settings."
                        )),
                    );
                }
            }
        });
    }

    /// Unlock the pending vault with its fingerprint unlock `record`. A record that no
    /// longer decrypts or opens the vault is deleted.
    pub fn unlock_with_fingerprint(
        &self,
        record: quick_unlock::Record,
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

        let state = *self;
        spawn_local(async move {
            let vault = source.vault_key();
            let stored = match quick_unlock::unlock(&vault, &record).await {
                Ok(stored) => stored,
                Err(UnlockError::Declined(message)) => {
                    fail(message);
                    return;
                }
                Err(UnlockError::Invalid(message)) => {
                    let _ = quick_unlock::forget(&vault).await;
                    fail(format!(
                        "{message} Fingerprint unlock was turned off for this vault; enter the password."
                    ));
                    return;
                }
            };
            let salt = params.salt();
            // Another client re-salted the file: run the KDF on the stored composite key.
            let resalted = salt != stored.kdf_salt;
            let transformed_key = if resalted {
                match kdf::derive_transformed_key(&params, &stored.composite).await {
                    Ok(key) => key,
                    Err(error) => {
                        fail(error);
                        return;
                    }
                }
            } else {
                stored.transformed.clone()
            };
            let document = match WasmDocument::open(&data, &stored.composite, &transformed_key) {
                Ok(document) => document,
                Err(_) => {
                    let _ = quick_unlock::forget(&vault).await;
                    fail(
                        "The keys stored for fingerprint unlock no longer open this vault, so fingerprint unlock was turned off. Enter the password."
                            .to_string(),
                    );
                    return;
                }
            };
            let restored = if resalted {
                stored.restore(&vault, &transformed_key, &salt).await
            } else {
                Ok(())
            };
            let id = state.open_session(document, source, salt);
            if let Err(error) = restored {
                state.set_error(
                    id,
                    Some(format!("Fingerprint unlock could not be updated: {error}")),
                );
            }
        });
    }

    /// Stores the keys of vault `id` for fingerprint unlock on this device.
    pub async fn enroll_fingerprint(self, id: SessionId) -> Result<(), String> {
        let keys = self.sessions.with_value(|sessions| {
            find_session(sessions, id).map(|session| {
                (
                    session.source.vault_key(),
                    session.source.name().to_string(),
                    Zeroizing::new(*session.local.composite_key()),
                    Zeroizing::new(*session.local.transformed_key()),
                    session.kdf_salt.clone(),
                )
            })
        });
        let Some((vault, label, composite, transformed, kdf_salt)) = keys else {
            return Err("The vault is no longer unlocked.".to_string());
        };
        quick_unlock::enroll(&vault, &label, &composite, &transformed, &kdf_salt).await
    }

    fn open_session(
        &self,
        document: WasmDocument,
        source: DatabaseSource,
        kdf_salt: Vec<u8>,
    ) -> SessionId {
        let id = self.next_session.get_value();
        self.next_session.set_value(id + 1);
        let tab = VaultTab {
            id,
            name: source.name().to_string(),
            dirty: false,
        };
        self.sessions.update_value(|sessions| {
            sessions.push(Session {
                id,
                base: document.clone(),
                local: document,
                source,
                kdf_salt,
                parked: ParkedView::default(),
            })
        });
        self.tabs.update(|tabs| tabs.push(tab));
        self.activate(id);
        id
    }

    /// Puts vault `id` on screen with the view state it had when it was left.
    pub fn activate(&self, id: SessionId) {
        if self.active.get_untracked() == Some(id) {
            return;
        }
        batch(|| {
            let parked = self
                .sessions
                .try_update_value(|sessions| {
                    find_session_mut(sessions, id)
                        .map(|session| std::mem::take(&mut session.parked))
                })
                .flatten();
            let Some(parked) = parked else {
                return;
            };
            self.park_active();
            self.pending.set(None);
            self.show_view(parked);
            self.active.set(Some(id));
            self.refresh_views();
        });
    }

    /// Shows the vault picker; unlocked vaults stay unlocked in their tabs.
    pub fn show_picker(&self) {
        batch(|| self.park_active());
    }

    /// Moves the view state of the vault on screen into its session and clears the
    /// signals.
    fn park_active(&self) {
        let Some(id) = self.active.get_untracked() else {
            return;
        };
        let parked = ParkedView {
            changes: self.changes.get_untracked(),
            save_notice: self.save_notice.get_untracked(),
            merge_conflicts: self.merge_conflicts.get_untracked(),
            error: self.error_message.get_untracked(),
            editor: self.editor.get_untracked(),
            selected_group: self.selected_group.get_untracked(),
            selected_tag: self.selected_tag.get_untracked(),
            selected_entry: self.selected_entry.get_untracked(),
            search_query: self.search_query.get_untracked(),
        };
        self.sessions.update_value(|sessions| {
            if let Some(session) = find_session_mut(sessions, id) {
                session.parked = parked;
            }
        });
        self.active.set(None);
        self.show_view(ParkedView::default());
        self.entries.set(Rc::new(Vec::new()));
        self.groups.set(Rc::new(Vec::new()));
        self.meta.set(None);
        self.custom_icons.set(Rc::new(Vec::new()));
        self.lock_requested.set(false);
        self.show_changes.set(false);
        self.show_settings.set(false);
    }

    fn show_view(&self, view: ParkedView) {
        let ParkedView {
            changes,
            save_notice,
            merge_conflicts,
            error,
            editor,
            selected_group,
            selected_tag,
            selected_entry,
            search_query,
        } = view;
        self.changes.set(changes);
        self.save_notice.set(save_notice);
        self.merge_conflicts.set(merge_conflicts);
        self.error_message.set(error);
        self.editor.set(editor);
        self.selected_group.set(selected_group);
        self.selected_tag.set(selected_tag);
        self.selected_entry.set(selected_entry);
        self.search_query.set(search_query);
    }

    /// Sets the error of vault `id`, shown now if it is on screen, otherwise when it is.
    fn set_error(&self, id: SessionId, error: Option<String>) {
        if self.active.get_untracked() == Some(id) {
            self.error_message.set(error);
        } else {
            self.sessions.update_value(|sessions| {
                if let Some(session) = find_session_mut(sessions, id) {
                    session.parked.error = error;
                }
            });
        }
    }

    fn set_dirty(&self, id: SessionId, dirty: bool) {
        let stale = self
            .tabs
            .with_untracked(|tabs| tabs.iter().any(|tab| tab.id == id && tab.dirty != dirty));
        if stale {
            self.tabs.update(|tabs| {
                if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == id) {
                    tab.dirty = dirty;
                }
            });
        }
    }

    /// Rebuild the reactive views from the active vault's local document.
    fn refresh_views(&self) {
        let views = self.with_active(|session| {
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

    /// Apply an edit to the active vault's local document and record it as unsaved.
    pub fn apply(&self, change: Change) -> Result<ChangeOutcome, String> {
        if self.saving.get_untracked() {
            return Err("Wait for the current save to finish.".to_string());
        }
        let not_open = || "No database is open.".to_string();
        let id = self.active.get_untracked().ok_or_else(not_open)?;
        let outcome = self
            .sessions
            .try_update_value(|sessions| {
                find_session_mut(sessions, id).map(|session| session.local.apply(change))
            })
            .flatten()
            .unwrap_or_else(|| Err(not_open()))?;
        if outcome.changed {
            self.changes
                .update(|changes| changes.push(outcome.summary.clone()));
            self.set_dirty(id, true);
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
        self.with_active(|session| session.local.document().attachment(entry, name))
            .flatten()
    }

    pub fn history_attachment(&self, entry: Uuid, index: usize, name: &str) -> Option<Vec<u8>> {
        self.with_active(|session| {
            session
                .local
                .document()
                .history_attachment(entry, index, name)
        })
        .flatten()
    }

    /// Whether the active vault has unsaved changes (tracked).
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
    /// Entries in the recycle bin only show while a recycle bin group is selected. A search
    /// covers the selected group and every group below it.
    pub fn filtered_entries(&self) -> Vec<EntryView> {
        let query = self.search_query.get().to_lowercase();
        let selected_group = self.selected_group.get();
        let selected_tag = self.selected_tag.get();
        let bin_selected = selected_group
            .and_then(|uuid| self.group(uuid))
            .is_some_and(|group| group.is_recycle_bin || group.in_recycle_bin);
        // Browsing lists a folder's own entries; a search also covers its subfolders.
        let scope: Option<Vec<Uuid>> = selected_group.map(|group| {
            if query.is_empty() {
                vec![group]
            } else {
                self.groups
                    .with(|groups| crate::model::subtree(groups, group))
            }
        });

        let mut filtered: Vec<EntryView> = self.entries.with(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    if let Some(tag) = &selected_tag {
                        if !entry.tags.contains(tag) {
                            return false;
                        }
                    } else if let Some(groups) = &scope {
                        if !groups.contains(&entry.group) {
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

    /// Save vault `id` to its source. For server vaults a stale revision triggers a
    /// three-way merge with the server copy, up to [`MAX_MERGE_ATTEMPTS`] times.
    pub async fn save_session(self, id: SessionId) -> Result<(), String> {
        if self.saving.get_untracked() {
            return Err("A save is already in progress.".to_string());
        }
        let snapshot = self.sessions.with_value(|sessions| {
            find_session(sessions, id).map(|session| SaveProgress {
                local: session.local.clone(),
                base: session.base.clone(),
                source: session.source.clone(),
                merged: false,
                conflicts: Vec::new(),
            })
        });
        let Some(mut progress) = snapshot else {
            return Err("The vault is no longer unlocked.".to_string());
        };

        self.saving.set(true);
        if self.active.get_untracked() == Some(id) {
            self.save_notice.set(None);
        }
        let result = match progress.source.clone() {
            DatabaseSource::Local { name } => save_local(&mut progress, &name),
            DatabaseSource::Server {
                id: server_id,
                name,
                ..
            } => save_server(&mut progress, &server_id, &name).await,
        };
        self.saving.set(false);

        if result.is_err() && !progress.merged {
            return result;
        }
        // Edits are refused while saving, so the session's local document is the one
        // this save started from and may be replaced by the merged result.
        let SaveProgress {
            local,
            base,
            source,
            merged,
            mut conflicts,
        } = progress;
        let saved = result.is_ok();
        let mut notice = saved.then(|| {
            if merged {
                "Saved with changes from the server"
            } else {
                "Saved"
            }
            .to_string()
        });
        let name = source.name().to_string();
        let active = self.active.get_untracked() == Some(id);
        let found = self
            .sessions
            .try_update_value(|sessions| {
                let session = find_session_mut(sessions, id)?;
                session.local = local;
                session.base = base;
                session.source = source;
                if saved && !active {
                    session.parked.changes.clear();
                    session.parked.save_notice = notice.take();
                    session.parked.merge_conflicts = std::mem::take(&mut conflicts);
                }
                Some(())
            })
            .flatten();
        if found.is_none() {
            // Locked while saving.
            return result;
        }
        self.tabs.update(|tabs| {
            if let Some(tab) = tabs.iter_mut().find(|tab| tab.id == id) {
                tab.name = name;
                if saved {
                    tab.dirty = false;
                }
            }
        });
        if active {
            if merged {
                self.refresh_views();
            }
            if saved {
                self.changes.set(Vec::new());
                self.save_notice.set(notice);
                self.merge_conflicts.set(conflicts);
            }
        }
        result
    }

    /// Save the vault on screen from a button or shortcut; failures go to its error
    /// banner.
    pub fn save_in_background(&self) {
        let Some(id) = self.active.get_untracked() else {
            return;
        };
        let state = *self;
        spawn_local(async move {
            let error = state
                .save_session(id)
                .await
                .err()
                .map(|error| format!("Save failed: {error}"));
            state.set_error(id, error);
        });
    }

    /// Lock the vault on screen, asking first when it has unsaved changes.
    pub fn request_lock(&self) {
        let Some(id) = self.active.get_untracked() else {
            return;
        };
        if self.changes.with_untracked(Vec::is_empty) {
            self.lock_session(id);
        } else {
            self.lock_requested.set(true);
        }
    }

    /// Drop the keys and document of vault `id`, discarding unsaved changes, and remove
    /// its tab. Locking the vault on screen shows the picker.
    pub fn lock_session(&self, id: SessionId) {
        batch(|| {
            if self.active.get_untracked() == Some(id) {
                self.park_active();
            }
            self.sessions
                .update_value(|sessions| sessions.retain(|session| session.id != id));
            self.tabs.update(|tabs| tabs.retain(|tab| tab.id != id));
        });
    }

    /// Lock every vault after inactivity. Unsaved changes are saved first; a vault whose
    /// save fails stays unlocked and shows why.
    pub async fn auto_lock(self) {
        let ids: Vec<SessionId> = self
            .tabs
            .with_untracked(|tabs| tabs.iter().map(|tab| tab.id).collect());
        let mut kept = None;
        for id in ids {
            // Re-read: earlier saves yield to the event loop.
            let dirty = self
                .tabs
                .with_untracked(|tabs| tabs.iter().find(|tab| tab.id == id).map(|tab| tab.dirty));
            match dirty {
                None => continue,
                Some(true) => {
                    if let Err(error) = self.save_session(id).await {
                        self.set_error(
                            id,
                            Some(format!(
                                "Auto-lock was cancelled because saving failed: {error}"
                            )),
                        );
                        kept.get_or_insert(id);
                        continue;
                    }
                }
                Some(false) => {}
            }
            self.lock_session(id);
        }
        if let Some(id) = kept {
            if self.active.get_untracked().is_none() {
                self.activate(id);
            }
        }
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
    // its own header with this session's composite key.
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
    progress.source = DatabaseSource::Server {
        id: id.to_string(),
        name: name.to_string(),
        revision: remote_revision,
    };
    progress.merged = true;
    Ok(())
}
