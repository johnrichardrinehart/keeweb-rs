//! Entry detail panel: read-only view, actions and the editor.

use keeweb_wasm::document::{Change, EntryView};
use leptos::*;
use uuid::Uuid;
use wasm_bindgen_futures::spawn_local;

use crate::components::dialog::{ConfirmDialog, GroupPicker};
use crate::components::icons::{Icon, KeepassIcon, UiIcon};
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

/// Icon of a copy button: a check mark while the value is on the clipboard.
fn copy_glyph(copied: impl Fn() -> bool + 'static) -> impl IntoView {
    move || {
        let icon = if copied() { Icon::Check } else { Icon::Copy };
        view! { <UiIcon icon=icon size=16 /> }
    }
}

/// Icon of a show/hide button for a concealed value.
fn reveal_glyph(shown: impl Fn() -> bool + 'static) -> impl IntoView {
    move || {
        let icon = if shown() { Icon::EyeOff } else { Icon::Eye };
        view! { <UiIcon icon=icon size=16 /> }
    }
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
    let has_meta = !entry.tags.is_empty() || entry.expires || in_recycle_bin;

    let copy =
        move |value: String, key: &'static str| copy_value(value, key.to_string(), copied_field);
    let is_copied = move |key: &'static str| move || copied_field.get().as_deref() == Some(key);
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
    let history_label = match history_len {
        0 => "No history".to_string(),
        1 => "1 version".to_string(),
        count => format!("{count} versions"),
    };

    view! {
        <div class="entry-detail-header">
            <div class="entry-detail-icon">
                <KeepassIcon icon_id=entry.icon_id custom_icon=entry.custom_icon fallback="" />
            </div>
            <div class="entry-detail-title-row">
                <h2>{title.clone()}</h2>
                <span class="entry-detail-path">
                    <UiIcon icon=Icon::Folder size=14 />
                    <span>{group_path}</span>
                </span>
                {has_meta.then(|| view! {
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
                                    <UiIcon icon=Icon::Clock size=14 />
                                    <span>{label}</span>
                                </div>
                            }
                        })}
                        {in_recycle_bin.then(|| view! { <span class="bin-badge">"In recycle bin"</span> })}
                    </div>
                })}
            </div>
            <button
                type="button"
                class="btn-icon panel-close"
                on:click=move |_| state.selected_entry.set(None)
                title="Close"
                aria-label="Close entry"
            >
                <span class="panel-close-x"><UiIcon icon=Icon::X /></span>
                <span class="panel-close-back"><UiIcon icon=Icon::ArrowLeft /></span>
            </button>
        </div>

        <div class="entry-toolbar" role="group" aria-label="Entry actions">
            <button
                type="button"
                class="btn btn-ghost btn-sm"
                disabled=move || state.saving.get()
                on:click=move |_| state.editor.set(Some(EntryEditor::Edit(uuid)))
                title="Edit"
                aria-label="Edit"
            >
                <UiIcon icon=Icon::Pencil size=16 />
                <span class="btn-label">"Edit"</span>
            </button>
            <button
                type="button"
                class="btn btn-ghost btn-sm"
                disabled=move || state.saving.get()
                on:click=duplicate
                title="Duplicate"
                aria-label="Duplicate"
            >
                <UiIcon icon=Icon::CopyPlus size=16 />
                <span class="btn-label">"Duplicate"</span>
            </button>
            <button
                type="button"
                class="btn btn-ghost btn-sm"
                disabled=move || state.saving.get()
                on:click=move |_| modal.set(Some(DetailModal::Move))
                title={if in_recycle_bin { "Restore from the recycle bin" } else { "Move to another group" }}
                aria-label={if in_recycle_bin { "Restore" } else { "Move" }}
            >
                <UiIcon icon={if in_recycle_bin { Icon::Undo } else { Icon::FolderInput }} size=16 />
                <span class="btn-label">{if in_recycle_bin { "Restore…" } else { "Move…" }}</span>
            </button>
            <button
                type="button"
                class="btn btn-ghost btn-sm"
                disabled={history_len == 0}
                on:click=move |_| modal.set(Some(DetailModal::History))
                title=history_label.clone()
                aria-label=format!("History: {history_label}")
            >
                <UiIcon icon=Icon::History size=16 />
                <span class="btn-label">"History"</span>
                {(history_len > 0).then(|| view! { <span class="count-badge">{history_len}</span> })}
            </button>
            <span class="toolbar-spacer"></span>
            <button
                type="button"
                class="btn btn-danger btn-sm"
                disabled=move || state.saving.get()
                on:click=move |_| {
                    if permanent_delete {
                        modal.set(Some(DetailModal::Delete));
                    } else {
                        delete();
                    }
                }
                title={if permanent_delete { "Delete permanently" } else { "Move to the recycle bin" }}
                aria-label="Delete"
            >
                <UiIcon icon=Icon::Trash size=16 />
                <span class="btn-label">"Delete"</span>
            </button>
        </div>

        <div class="entry-detail-body">
            <div class="field-group">
                <label>"Username"</label>
                <div class="field-value-row">
                    <input type="text" class="field-input" value=username readonly=true aria-label="Username" />
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        class:copied=is_copied("username")
                        on:click=move |_| copy(username_for_copy.clone(), "username")
                        title="Copy username"
                        aria-label="Copy username"
                    >
                        {copy_glyph(is_copied("username"))}
                    </button>
                </div>
            </div>

            <div class="field-group">
                <label>"Password"</label>
                <div class="field-value-row">
                    <input
                        type=move || if show_password.get() { "text" } else { "password" }
                        class="field-input field-input-secret"
                        value=password
                        readonly=true
                        autocomplete="off"
                        aria-label="Password"
                    />
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        on:click=move |_| show_password.update(|v| *v = !*v)
                        title=move || if show_password.get() { "Hide password" } else { "Show password" }
                        aria-label=move || if show_password.get() { "Hide password" } else { "Show password" }
                    >
                        {reveal_glyph(move || show_password.get())}
                    </button>
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        class:copied=is_copied("password")
                        on:click=move |_| copy(password_for_copy.clone(), "password")
                        title="Copy password"
                        aria-label="Copy password"
                    >
                        {copy_glyph(is_copied("password"))}
                    </button>
                </div>
            </div>

            {otp.map(|otp_value| view! { <TotpField otp_value=otp_value copied_field=copied_field /> })}

            <div class="field-group">
                <label>"URL"</label>
                <div class="field-value-row">
                    <input type="text" class="field-input" value=url.clone() readonly=true aria-label="URL" />
                    {(!url.is_empty()).then(|| view! {
                        <a
                            href=url_for_link
                            target="_blank"
                            rel="noopener noreferrer"
                            class="btn-icon btn-icon-sm"
                            title="Open URL"
                            aria-label="Open URL"
                        >
                            <UiIcon icon=Icon::ExternalLink size=16 />
                        </a>
                    })}
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        class:copied=is_copied("url")
                        on:click=move |_| copy(url_for_copy.clone(), "url")
                        title="Copy URL"
                        aria-label="Copy URL"
                    >
                        {copy_glyph(is_copied("url"))}
                    </button>
                </div>
            </div>

            <div class="field-group">
                <label>"Notes"</label>
                <textarea class="field-textarea" readonly=true aria-label="Notes">{notes}</textarea>
            </div>

            {(!custom_fields.is_empty()).then(|| view! {
                <section class="detail-section">
                    <h3 class="section-header">"Custom fields"</h3>
                    {custom_fields.into_iter().map(|field| view! {
                        <CustomFieldView
                            key=field.key
                            value=field.value
                            protected=field.protected
                            copied_field=copied_field
                        />
                    }).collect_view()}
                </section>
            })}

            {(!entry.attachments.is_empty()).then(|| view! {
                <section class="detail-section">
                    <h3 class="section-header">"Attachments"</h3>
                    <div class="attachments-list">
                        {entry.attachments.iter().map(|attachment| {
                            let name = attachment.name.clone();
                            let name_for_download = attachment.name.clone();
                            view! {
                                <div class="attachment-item">
                                    <UiIcon icon=Icon::Paperclip size=16 />
                                    <span class="attachment-name">{name.clone()}</span>
                                    <span class="attachment-size">{model::format_size(attachment.size)}</span>
                                    <button
                                        type="button"
                                        class="btn-icon btn-icon-sm"
                                        title="Download"
                                        aria-label=format!("Download {name}")
                                        on:click=move |_| download_attachment(state, uuid, &name_for_download)
                                    >
                                        <UiIcon icon=Icon::Download size=16 />
                                    </button>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                </section>
            })}

            <EntryProperties entry=entry.clone() />
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
        <section class="detail-section">
            <h3 class="section-header">"Properties"</h3>
            <dl class="entry-properties">
                {rows.into_iter().map(|(label, value)| view! {
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                }).collect_view()}
            </dl>
        </section>
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
    let is_copied = move || copied_field.get().as_deref() == Some(copy_key_check.as_str());
    let label = key.clone();

    view! {
        <div class="field-group">
            <label>
                {key}
                {protected.then(|| view! {
                    <span class="protected-badge" title="Protected field">
                        <UiIcon icon=Icon::Lock size=12 />
                        <span class="visually-hidden">" (protected)"</span>
                    </span>
                })}
            </label>
            <div class="field-value-row">
                <input
                    type=move || if shown.get() { "text" } else { "password" }
                    class="field-input"
                    class:field-input-secret=protected
                    value=value
                    readonly=true
                    autocomplete="off"
                    aria-label=label.clone()
                />
                {protected.then(|| view! {
                    <button
                        type="button"
                        class="btn-icon btn-icon-sm"
                        on:click=move |_| shown.update(|v| *v = !*v)
                        title=move || if shown.get() { "Hide value" } else { "Show value" }
                        aria-label=move || if shown.get() { "Hide value" } else { "Show value" }
                    >
                        {reveal_glyph(move || shown.get())}
                    </button>
                })}
                <button
                    type="button"
                    class="btn-icon btn-icon-sm"
                    class:copied=is_copied.clone()
                    on:click=move |_| copy_value(value_for_copy.clone(), copy_key.clone(), copied_field)
                    title="Copy value"
                    aria-label=format!("Copy {label}")
                >
                    {copy_glyph(is_copied)}
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
    let is_copied = move || copied_field.get().as_deref() == Some("totp");

    view! {
        <div class="field-group totp-field">
            <label>"One-time code"</label>
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
                                <div class="totp-timer" title=format!("{remaining} seconds left")>
                                    <svg viewBox="0 0 36 36" class="totp-progress-ring" aria-hidden="true">
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
                                    </svg>
                                    <span class="totp-timer-text">{remaining}</span>
                                </div>
                            </div>
                        }.into_view()
                    }
                }}
                <button
                    type="button"
                    class="btn-icon btn-icon-sm"
                    class:copied=is_copied
                    on:click=copy_totp
                    title="Copy TOTP code"
                    aria-label="Copy TOTP code"
                >
                    {copy_glyph(is_copied)}
                </button>
            </div>
        </div>
    }
}
