//! Entry detail panel: read-only view, actions and the editor.

use keeweb_wasm::document::{Change, EntryView};
use leptos::*;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;

use crate::components::dialog::{ConfirmDialog, GroupPicker};
use crate::components::icons::KeepassIcon;
use crate::model::{self, NOTES, PASSWORD, URL, USER_NAME};
use crate::state::{AppState, EntryEditor};
use crate::utils::{clipboard, files};

mod editor;
mod history;
mod totp;

pub use editor::EntryEditorPanel;
use history::HistoryViewer;
use totp::TotpConfig;

/// Detail panel: the editor while editing, otherwise the selected entry.
#[component]
pub fn EntryPanel() -> impl IntoView {
    let state = expect_context::<AppState>();
    move || match state.editor.get() {
        Some(mode) => view! { <EntryEditorPanel mode=mode /> }.into_view(),
        None => view! { <EntryDetail /> }.into_view(),
    }
}

/// Which modal the detail view shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailModal {
    History,
    Move,
    Delete,
}

/// Entry detail component
#[component]
pub fn EntryDetail() -> impl IntoView {
    let state = expect_context::<AppState>();

    // Created outside the per-entry closure so they survive re-renders caused by
    // edits of the same entry (e.g. deleting a history version).
    let show_password = create_rw_signal(false);
    let copied_field = create_rw_signal(Option::<String>::None);
    let modal = create_rw_signal(Option::<DetailModal>::None);

    create_effect(move |previous: Option<Option<Uuid>>| {
        let current = state.selected_entry.get();
        if previous.is_some_and(|previous| previous != current) {
            show_password.set(false);
            modal.set(None);
        }
        current
    });

    view! {
        <div class="entry-detail">
            {move || match state.get_selected_entry() {
                None => view! { <div class="no-selection">"Select an entry"</div> }.into_view(),
                Some(entry) => view! {
                    <EntryDetailContent
                        entry=entry
                        show_password=show_password
                        copied_field=copied_field
                        modal=modal
                    />
                }.into_view(),
            }}
        </div>
    }
}

fn copy_value(value: String, key: String, copied: RwSignal<Option<String>>) {
    spawn_local(async move {
        if clipboard::copy_to_clipboard(&value).await.is_ok() {
            copied.set(Some(key));
            set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
        }
    });
}

/// Entry detail content (separate component to avoid closure issues)
#[component]
fn EntryDetailContent(
    entry: EntryView,
    show_password: RwSignal<bool>,
    copied_field: RwSignal<Option<String>>,
    modal: RwSignal<Option<DetailModal>>,
) -> impl IntoView {
    let state = expect_context::<AppState>();
    let uuid = entry.uuid;
    let title = model::display_title(&entry);
    let username = model::field(&entry, USER_NAME).to_string();
    let password = model::field(&entry, PASSWORD).to_string();
    let url = model::field(&entry, URL).to_string();
    let notes = model::field(&entry, NOTES).to_string();
    let otp = model::otp_value(&entry).map(str::to_string);
    let custom_fields: Vec<_> = entry
        .strings
        .iter()
        .filter(|field| !model::is_standard_field(&field.key) && !model::is_otp_field(&field.key))
        .cloned()
        .collect();
    let in_recycle_bin = entry.in_recycle_bin;
    let permanent_delete = in_recycle_bin
        || !state
            .meta
            .with_untracked(|meta| meta.as_ref().is_some_and(|meta| meta.recycle_bin_enabled));
    let history_len = entry.history.len();
    let group_uuid = entry.group;
    let group_path = state
        .groups
        .with_untracked(|groups| model::group_path(groups, group_uuid));

    let copy =
        move |value: String, key: &'static str| copy_value(value, key.to_string(), copied_field);
    let username_for_copy = username.clone();
    let password_for_copy = password.clone();
    let url_for_copy = url.clone();
    let url_for_link = url.clone();

    let duplicate = move |_| {
        if let Some(outcome) = state.apply_or_report(Change::DuplicateEntry { uuid }) {
            if let Some(created) = outcome.created {
                state.selected_entry.set(Some(created));
            }
        }
    };
    let delete = move || {
        modal.set(None);
        if state
            .apply_or_report(Change::DeleteEntry { uuid })
            .is_some()
        {
            state.selected_entry.set(None);
        }
    };

    let entry_for_history = entry.clone();
    let title_for_modal = title.clone();

    view! {
        <div class="entry-detail-header">
            <div class="entry-detail-icon">
                <KeepassIcon icon_id=entry.icon_id custom_icon=entry.custom_icon fallback="" />
            </div>
            <div class="entry-detail-title-row">
                <h2>{title.clone()}</h2>
                <span class="entry-detail-path">{group_path}</span>
                <div class="entry-meta-row">
                    {(!entry.tags.is_empty()).then(|| view! {
                        <div class="tags-container">
                            {entry.tags.iter().map(|tag| view! { <span class="tag">{tag.clone()}</span> }).collect_view()}
                        </div>
                    })}
                    {entry.expires.then(|| {
                        let expired = model::is_expired(entry.expiry_time);
                        let label = match entry.expiry_time {
                            Some(time) if expired => format!("Expired {}", model::format_relative(time)),
                            Some(time) => format!("Expires {}", model::format_relative(time)),
                            None => "Expires".to_string(),
                        };
                        let exact = entry.expiry_time.map(model::format_local).unwrap_or_default();
                        view! {
                            <div class="expiry-badge" class:expired=expired title=exact>
                                <ExpiryIcon />
                                <span>{label}</span>
                            </div>
                        }
                    })}
                    {in_recycle_bin.then(|| view! { <span class="bin-badge">"In recycle bin"</span> })}
                </div>
            </div>
            <button class="btn-icon" on:click=move |_| state.selected_entry.set(None) title="Close">
                <CloseIcon />
            </button>
        </div>

        <div class="entry-detail-body">
            <div class="field-group">
                <label>"Username"</label>
                <div class="field-value-row">
                    <input type="text" class="field-input" value=username readonly=true />
                    <button
                        class="btn-icon"
                        class:copied=move || copied_field.get().as_deref() == Some("username")
                        on:click=move |_| copy(username_for_copy.clone(), "username")
                        title="Copy username"
                    >
                        <CopyIcon />
                    </button>
                </div>
            </div>

            <div class="field-group">
                <label>"Password"</label>
                <div class="field-value-row">
                    <input
                        type=move || if show_password.get() { "text" } else { "password" }
                        class="field-input"
                        value=password
                        readonly=true
                        autocomplete="off"
                    />
                    <button
                        class="btn-icon"
                        on:click=move |_| show_password.update(|v| *v = !*v)
                        title=move || if show_password.get() { "Hide password" } else { "Show password" }
                    >
                        {move || if show_password.get() {
                            view! { <EyeOffIcon /> }.into_view()
                        } else {
                            view! { <EyeIcon /> }.into_view()
                        }}
                    </button>
                    <button
                        class="btn-icon"
                        class:copied=move || copied_field.get().as_deref() == Some("password")
                        on:click=move |_| copy(password_for_copy.clone(), "password")
                        title="Copy password"
                    >
                        <CopyIcon />
                    </button>
                </div>
            </div>

            {otp.map(|otp_value| view! { <TotpField otp_value=otp_value copied_field=copied_field /> })}

            <div class="field-group">
                <label>"URL"</label>
                <div class="field-value-row">
                    <input type="text" class="field-input" value=url.clone() readonly=true />
                    {(!url.is_empty()).then(|| view! {
                        <a
                            href=url_for_link
                            target="_blank"
                            rel="noopener noreferrer"
                            class="btn-icon"
                            title="Open URL"
                        >
                            <LinkIcon />
                        </a>
                    })}
                    <button
                        class="btn-icon"
                        class:copied=move || copied_field.get().as_deref() == Some("url")
                        on:click=move |_| copy(url_for_copy.clone(), "url")
                        title="Copy URL"
                    >
                        <CopyIcon />
                    </button>
                </div>
            </div>

            <div class="field-group">
                <label>"Notes"</label>
                <textarea class="field-textarea" readonly=true>{notes}</textarea>
            </div>

            {(!custom_fields.is_empty()).then(|| view! {
                <div class="custom-attributes-section">
                    <h3 class="section-header">"Custom Fields"</h3>
                    {custom_fields.into_iter().map(|field| view! {
                        <CustomFieldView
                            key=field.key
                            value=field.value
                            protected=field.protected
                            copied_field=copied_field
                        />
                    }).collect_view()}
                </div>
            })}

            {(!entry.attachments.is_empty()).then(|| view! {
                <div class="attachments-section">
                    <h3 class="section-header">"Attachments"</h3>
                    <div class="attachments-list">
                        {entry.attachments.iter().map(|attachment| {
                            let name = attachment.name.clone();
                            let name_for_download = attachment.name.clone();
                            view! {
                                <div class="attachment-item">
                                    <AttachmentIcon />
                                    <span class="attachment-name">{name}</span>
                                    <span class="attachment-size">{model::format_size(attachment.size)}</span>
                                    <button
                                        class="btn-icon"
                                        title="Download"
                                        on:click=move |_| download_attachment(state, uuid, &name_for_download)
                                    >
                                        <DownloadIcon />
                                    </button>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                </div>
            })}

            <EntryProperties entry=entry.clone() />
        </div>

        <div class="entry-detail-footer">
            <button
                class="btn btn-secondary"
                disabled={history_len == 0}
                on:click=move |_| modal.set(Some(DetailModal::History))
                title={if history_len > 0 { format!("{history_len} versions") } else { "No history".to_string() }}
            >
                <HistoryIcon />
                " History"
                {(history_len > 0).then(|| view! { <span class="history-count">{history_len}</span> })}
            </button>
            <span class="footer-spacer"></span>
            <button
                class="btn btn-secondary"
                disabled=move || state.saving.get()
                on:click=move |_| state.editor.set(Some(EntryEditor::Edit(uuid)))
            >
                "Edit"
            </button>
            <button class="btn btn-secondary" disabled=move || state.saving.get() on:click=duplicate>
                "Duplicate"
            </button>
            <button
                class="btn btn-secondary"
                disabled=move || state.saving.get()
                on:click=move |_| modal.set(Some(DetailModal::Move))
            >
                {if in_recycle_bin { "Restore…" } else { "Move…" }}
            </button>
            <button
                class="btn btn-danger"
                disabled=move || state.saving.get()
                on:click=move |_| {
                    if permanent_delete {
                        modal.set(Some(DetailModal::Delete));
                    } else {
                        delete();
                    }
                }
                title={if permanent_delete { "Delete permanently" } else { "Move to the recycle bin" }}
            >
                "Delete"
            </button>
        </div>

        {move || match modal.get() {
            Some(DetailModal::History) => view! {
                <HistoryViewer
                    entry=entry_for_history.clone()
                    on_close=move |_| modal.set(None)
                />
            }.into_view(),
            Some(DetailModal::Move) => view! {
                <GroupPicker
                    title=format!("Move “{}”", title_for_modal)
                    current=Some(group_uuid)
                    excluded=Vec::new()
                    on_pick=move |group| {
                        modal.set(None);
                        state.apply_or_report(Change::MoveEntry { uuid, group });
                    }
                    on_close=move |_| modal.set(None)
                />
            }.into_view(),
            Some(DetailModal::Delete) => view! {
                <ConfirmDialog
                    title="Delete entry permanently?"
                    message=format!("“{}” will be deleted permanently when you save.", title_for_modal)
                    confirm_label="Delete permanently"
                    on_confirm=move |_| delete()
                    on_close=move |_| modal.set(None)
                />
            }.into_view(),
            None => ().into_view(),
        }}
    }
}

fn download_attachment(state: AppState, entry: Uuid, name: &str) {
    match state.attachment(entry, name) {
        Some(bytes) => {
            if let Err(error) = files::download_bytes(name, &bytes) {
                state.error_message.set(Some(error));
            }
        }
        None => state
            .error_message
            .set(Some(format!("Attachment “{name}” not found."))),
    }
}

/// Less frequently needed properties.
#[component]
fn EntryProperties(entry: EntryView) -> impl IntoView {
    let mut rows: Vec<(&'static str, String)> = Vec::new();
    if !entry.override_url.is_empty() {
        rows.push(("Override URL", entry.override_url.clone()));
    }
    let auto_type = &entry.auto_type;
    rows.push((
        "Auto-Type",
        if !auto_type.enabled {
            "Disabled".to_string()
        } else if auto_type.default_sequence.is_empty() {
            "Default sequence".to_string()
        } else {
            auto_type.default_sequence.clone()
        },
    ));
    if !auto_type.associations.is_empty() {
        rows.push((
            "Windows",
            auto_type
                .associations
                .iter()
                .map(|association| association.window.clone())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if let Some(time) = entry.times.creation {
        rows.push(("Created", model::format_local(time)));
    }
    if let Some(time) = entry.times.last_modification {
        rows.push(("Modified", model::format_local(time)));
    }

    view! {
        <dl class="entry-properties">
            {rows.into_iter().map(|(label, value)| view! {
                <dt>{label}</dt>
                <dd>{value}</dd>
            }).collect_view()}
        </dl>
    }
}

#[component]
fn CustomFieldView(
    key: String,
    value: String,
    protected: bool,
    copied_field: RwSignal<Option<String>>,
) -> impl IntoView {
    let shown = create_rw_signal(!protected);
    let copy_key = format!("field:{key}");
    let copy_key_check = copy_key.clone();
    let value_for_copy = value.clone();

    view! {
        <div class="field-group">
            <label>
                {key}
                {protected.then(|| view! { <span class="protected-badge" title="Protected field">" 🔒"</span> })}
            </label>
            <div class="field-value-row">
                <input
                    type=move || if shown.get() { "text" } else { "password" }
                    class="field-input"
                    value=value
                    readonly=true
                    autocomplete="off"
                />
                {protected.then(|| view! {
                    <button
                        class="btn-icon"
                        on:click=move |_| shown.update(|v| *v = !*v)
                        title=move || if shown.get() { "Hide value" } else { "Show value" }
                    >
                        {move || if shown.get() {
                            view! { <EyeOffIcon /> }.into_view()
                        } else {
                            view! { <EyeIcon /> }.into_view()
                        }}
                    </button>
                })}
                <button
                    class="btn-icon"
                    class:copied=move || copied_field.get().as_deref() == Some(copy_key_check.as_str())
                    on:click=move |_| copy_value(value_for_copy.clone(), copy_key.clone(), copied_field)
                    title="Copy value"
                >
                    <CopyIcon />
                </button>
            </div>
        </div>
    }
}

/// TOTP field component
#[component]
fn TotpField(otp_value: String, copied_field: RwSignal<Option<String>>) -> impl IntoView {
    let totp_code = create_rw_signal(String::new());
    let totp_remaining = create_rw_signal(0u32);
    let totp_period = create_rw_signal(30u32);
    let totp_error = create_rw_signal(Option::<String>::None);

    let generate =
        move |otp: &str| match TotpConfig::parse(otp).and_then(|config| config.generate()) {
            Ok(result) => {
                totp_code.set(result.code);
                totp_remaining.set(result.remaining);
                totp_period.set(result.period);
                totp_error.set(None);
            }
            Err(error) => totp_error.set(Some(error)),
        };
    generate(&otp_value);

    let handle = set_interval_with_handle(
        move || generate(&otp_value),
        std::time::Duration::from_secs(1),
    );
    on_cleanup(move || {
        if let Ok(handle) = handle {
            handle.clear();
        }
    });

    let copy_totp =
        move |_| copy_value(totp_code.get_untracked(), "totp".to_string(), copied_field);

    view! {
        <div class="field-group totp-field">
            <label>"TOTP"</label>
            <div class="field-value-row">
                {move || {
                    if let Some(error) = totp_error.get() {
                        view! { <span class="totp-error">{error}</span> }.into_view()
                    } else {
                        let remaining = totp_remaining.get();
                        let progress = remaining as f64 / totp_period.get().max(1) as f64 * 100.0;
                        view! {
                            <div class="totp-display">
                                <span class="totp-code">{totp_code.get()}</span>
                                <div class="totp-timer">
                                    <svg viewBox="0 0 36 36" class="totp-progress-ring">
                                        <path
                                            class="totp-progress-bg"
                                            d="M18 2.0845
                                               a 15.9155 15.9155 0 0 1 0 31.831
                                               a 15.9155 15.9155 0 0 1 0 -31.831"
                                        />
                                        <path
                                            class="totp-progress-bar"
                                            stroke-dasharray=format!("{}, 100", progress)
                                            d="M18 2.0845
                                               a 15.9155 15.9155 0 0 1 0 31.831
                                               a 15.9155 15.9155 0 0 1 0 -31.831"
                                        />
                                        <text x="18" y="21" class="totp-timer-text">{remaining}</text>
                                    </svg>
                                </div>
                            </div>
                        }.into_view()
                    }
                }}
                <button
                    class="btn-icon"
                    class:copied=move || copied_field.get().as_deref() == Some("totp")
                    on:click=copy_totp
                    title="Copy TOTP code"
                >
                    <CopyIcon />
                </button>
            </div>
        </div>
    }
}

/// Copy icon
#[component]
pub(crate) fn CopyIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
        </svg>
    }
}

/// Eye icon (show password)
#[component]
pub(crate) fn EyeIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
        </svg>
    }
}

/// Eye-off icon (hide password)
#[component]
pub(crate) fn EyeOffIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>
        </svg>
    }
}

/// Link/external icon
#[component]
fn LinkIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/>
        </svg>
    }
}

/// Generate/refresh icon
#[component]
pub(crate) fn GenerateIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
        </svg>
    }
}

/// Attachment/file icon
#[component]
pub(crate) fn AttachmentIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/>
        </svg>
    }
}

#[component]
pub(crate) fn DownloadIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/>
        </svg>
    }
}

#[component]
pub(crate) fn CloseIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="20" height="20">
            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
        </svg>
    }
}

/// Expiry/clock icon
#[component]
fn ExpiryIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="14" height="14">
            <path fill="currentColor" d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/>
        </svg>
    }
}

/// History icon
#[component]
fn HistoryIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/>
        </svg>
    }
}
