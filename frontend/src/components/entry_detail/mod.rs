//! Entry detail/editor component

use leptos::*;
use std::collections::HashMap;
use wasm_bindgen_futures::spawn_local;

use crate::components::password_generator::PasswordGenerator;
use crate::state::{AppState, AttachmentInfo, HistoryEntryInfo};
use crate::utils::clipboard;

mod totp;
use totp::TotpConfig;

/// Entry detail component
#[component]
pub fn EntryDetail() -> impl IntoView {
    let state = expect_context::<AppState>();

    let show_password = create_rw_signal(false);
    let show_generator = create_rw_signal(false);
    let show_history = create_rw_signal(false);
    let copied_field = create_rw_signal(Option::<String>::None);

    view! {
        <div class="entry-detail">
            {move || {
                let entry = state.get_selected_entry();
                match entry {
                    None => view! { <div class="no-selection">"Select an entry"</div> }.into_view(),
                    Some(e) => {
                        let title = e.title.clone();
                        let username = e.username.clone();
                        let password = e.password.clone().unwrap_or_default();
                        let url = e.url.clone();
                        let notes = e.notes.clone();
                        let otp = e.otp.clone();
                        let custom_attributes = e.custom_attributes.clone();
                        let attachments = e.attachments.clone();
                        let tags = e.tags.clone();
                        let expires = e.expires;
                        let expiry_time = e.expiry_time.clone();
                        let history = e.history.clone();
                        let url_for_link = url.clone();
                        let url_is_empty = url.is_empty();

                        view! {
                            <EntryDetailContent
                                title=title
                                username=username
                                password=password
                                url=url
                                url_for_link=url_for_link
                                url_is_empty=url_is_empty
                                notes=notes
                                otp=otp
                                custom_attributes=custom_attributes
                                attachments=attachments
                                tags=tags
                                expires=expires
                                expiry_time=expiry_time
                                history=history
                                show_password=show_password
                                show_generator=show_generator
                                show_history=show_history
                                copied_field=copied_field
                            />
                        }.into_view()
                    }
                }
            }}
        </div>
    }
}

/// Entry detail content (separate component to avoid closure issues)
#[component]
fn EntryDetailContent(
    title: String,
    username: String,
    password: String,
    url: String,
    url_for_link: String,
    url_is_empty: bool,
    notes: String,
    otp: Option<String>,
    custom_attributes: HashMap<String, String>,
    attachments: Vec<AttachmentInfo>,
    tags: Vec<String>,
    expires: bool,
    expiry_time: Option<String>,
    history: Vec<HistoryEntryInfo>,
    show_password: RwSignal<bool>,
    show_generator: RwSignal<bool>,
    show_history: RwSignal<bool>,
    copied_field: RwSignal<Option<String>>,
) -> impl IntoView {
    let state = expect_context::<AppState>();

    // Copy handlers
    let username_for_copy = username.clone();
    let password_for_copy = password.clone();
    let url_for_copy = url.clone();

    let copy_username = move |_| {
        let value = username_for_copy.clone();
        let copied = copied_field;
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&value).await.is_ok() {
                copied.set(Some("username".to_string()));
                set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
            }
        });
    };

    let copy_password = move |_| {
        let value = password_for_copy.clone();
        let copied = copied_field;
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&value).await.is_ok() {
                copied.set(Some("password".to_string()));
                set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
            }
        });
    };

    let copy_url = move |_| {
        let value = url_for_copy.clone();
        let copied = copied_field;
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&value).await.is_ok() {
                copied.set(Some("url".to_string()));
                set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
            }
        });
    };

    // Password input ref for dynamic type switching
    let password_input_ref = create_node_ref::<leptos::html::Input>();
    let password_for_display = password.clone();

    // Update password input type when show_password changes
    create_effect(move |_| {
        let show = show_password.get();
        if let Some(input) = password_input_ref.get() {
            let input_type = if show { "text" } else { "password" };
            let _ = input.set_attribute("type", input_type);
        }
    });

    // Clone title for use in header (original is used in history viewer)
    let title_for_header = title.clone();

    view! {
        <div class="entry-detail-header">
            <div class="entry-detail-title-row">
                <h2>{title_for_header}</h2>
                <div class="entry-meta-row">
                    {if !tags.is_empty() {
                        view! {
                            <div class="tags-container">
                                {tags.into_iter().map(|tag| {
                                    view! { <span class="tag">{tag}</span> }
                                }).collect_view()}
                            </div>
                        }.into_view()
                    } else {
                        view! { <span></span> }.into_view()
                    }}
                    {if expires {
                        let is_expired = is_entry_expired(&expiry_time);
                        let expiry_display = format_expiry_time(&expiry_time);
                        view! {
                            <div class="expiry-badge" class:expired=is_expired>
                                <ExpiryIcon />
                                <span>{expiry_display}</span>
                            </div>
                        }.into_view()
                    } else {
                        view! { <span></span> }.into_view()
                    }}
                </div>
            </div>
            <button class="btn-icon" on:click=move |_| state.selected_entry.set(None) title="Close">
                <svg viewBox="0 0 24 24" width="20" height="20">
                    <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                </svg>
            </button>
        </div>

        <div class="entry-detail-body">
            // Username field
            <div class="field-group">
                <label>"Username"</label>
                <div class="field-value-row">
                    <input
                        type="text"
                        class="field-input"
                        value=username
                        readonly=true
                    />
                    <button
                        class="btn-icon"
                        class:copied=move || copied_field.get() == Some("username".to_string())
                        on:click=copy_username
                        title="Copy username"
                    >
                        <CopyIcon />
                    </button>
                </div>
            </div>

            // Password field
            <div class="field-group">
                <label>"Password"</label>
                <div class="field-value-row">
                    <input
                        type="password"
                        class="field-input"
                        value=password_for_display
                        node_ref=password_input_ref
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
                        class:copied=move || copied_field.get() == Some("password".to_string())
                        on:click=copy_password
                        title="Copy password"
                    >
                        <CopyIcon />
                    </button>
                    <button
                        class="btn-icon"
                        on:click=move |_| show_generator.update(|v| *v = !*v)
                        title="Generate password"
                    >
                        <GenerateIcon />
                    </button>
                </div>
            </div>

            // TOTP field (only shown if entry has OTP configured)
            {if let Some(otp_value) = otp.clone() {
                view! { <TotpField otp_value=otp_value copied_field=copied_field /> }.into_view()
            } else {
                view! { <span></span> }.into_view()
            }}

            // URL field
            <div class="field-group">
                <label>"URL"</label>
                <div class="field-value-row">
                    <input
                        type="text"
                        class="field-input"
                        value=url
                        readonly=true
                    />
                    {if !url_is_empty {
                        view! {
                            <a
                                href=url_for_link
                                target="_blank"
                                rel="noopener noreferrer"
                                class="btn-icon"
                                title="Open URL"
                            >
                                <LinkIcon />
                            </a>
                        }.into_view()
                    } else {
                        view! { <span></span> }.into_view()
                    }}
                    <button
                        class="btn-icon"
                        class:copied=move || copied_field.get() == Some("url".to_string())
                        on:click=copy_url
                        title="Copy URL"
                    >
                        <CopyIcon />
                    </button>
                </div>
            </div>

            // Notes field
            <div class="field-group">
                <label>"Notes"</label>
                <textarea
                    class="field-textarea"
                    readonly=true
                >{notes}</textarea>
            </div>

            // Custom attributes section
            {if !custom_attributes.is_empty() {
                let mut attrs: Vec<_> = custom_attributes.into_iter().collect();
                attrs.sort_by(|a, b| a.0.cmp(&b.0)); // Sort alphabetically by key

                view! {
                    <div class="custom-attributes-section">
                        <h3 class="section-header">"Custom Attributes"</h3>
                        {attrs.into_iter().map(|(key, value)| {
                            let key_for_copy = key.clone();
                            let value_for_copy = value.clone();
                            let copied = copied_field;

                            let copy_value = move |_| {
                                let val = value_for_copy.clone();
                                let key = key_for_copy.clone();
                                spawn_local(async move {
                                    if clipboard::copy_to_clipboard(&val).await.is_ok() {
                                        copied.set(Some(format!("attr_{}", key)));
                                        set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
                                    }
                                });
                            };

                            let key_display = key.clone();
                            let key_for_check = key.clone();

                            view! {
                                <div class="field-group">
                                    <label>{key_display}</label>
                                    <div class="field-value-row">
                                        <input
                                            type="text"
                                            class="field-input"
                                            value=value
                                            readonly=true
                                        />
                                        <button
                                            class="btn-icon"
                                            class:copied=move || copied_field.get() == Some(format!("attr_{}", key_for_check))
                                            on:click=copy_value
                                            title="Copy value"
                                        >
                                            <CopyIcon />
                                        </button>
                                    </div>
                                </div>
                            }
                        }).collect_view()}
                    </div>
                }.into_view()
            } else {
                view! { <span></span> }.into_view()
            }}

            // Attachments section
            {if !attachments.is_empty() {
                view! {
                    <div class="attachments-section">
                        <h3 class="section-header">"Attachments"</h3>
                        <div class="attachments-list">
                            {attachments.into_iter().map(|attachment| {
                                let name = attachment.name.clone();
                                let size_display = attachment.size.map(|s| format_file_size(s)).unwrap_or_default();

                                view! {
                                    <div class="attachment-item">
                                        <AttachmentIcon />
                                        <span class="attachment-name">{name}</span>
                                        {if !size_display.is_empty() {
                                            view! { <span class="attachment-size">{size_display}</span> }.into_view()
                                        } else {
                                            view! { <span></span> }.into_view()
                                        }}
                                    </div>
                                }
                            }).collect_view()}
                        </div>
                        <p class="attachments-note">"Attachment download not yet supported"</p>
                    </div>
                }.into_view()
            } else {
                view! { <span></span> }.into_view()
            }}
        </div>

        <div class="entry-detail-footer">
            {
                let history_len = history.len();
                let has_history = history_len > 0;
                view! {
                    <button
                        class="btn btn-secondary"
                        disabled=!has_history
                        on:click=move |_| show_history.set(true)
                        title=move || if has_history { format!("{} versions", history_len) } else { "No history".to_string() }
                    >
                        <HistoryIcon />
                        " History"
                        {if has_history {
                            view! { <span class="history-count">{history_len}</span> }.into_view()
                        } else {
                            view! { <span></span> }.into_view()
                        }}
                    </button>
                }
            }
            <button class="btn btn-secondary" disabled=true title="Coming soon">
                "Edit"
            </button>
            <button class="btn btn-danger" disabled=true title="Coming soon">
                "Delete"
            </button>
        </div>

        // Password generator modal
        <Show when=move || show_generator.get()>
            <PasswordGenerator on_close=move || show_generator.set(false) />
        </Show>

        // History viewer modal
        <Show when=move || show_history.get()>
            <HistoryViewer
                history=history.clone()
                entry_title=title.clone()
                on_close=move || show_history.set(false)
            />
        </Show>
    }
}

/// Copy icon
#[component]
fn CopyIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
        </svg>
    }
}

/// Eye icon (show password)
#[component]
fn EyeIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
        </svg>
    }
}

/// Eye-off icon (hide password)
#[component]
fn EyeOffIcon() -> impl IntoView {
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
fn GenerateIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
        </svg>
    }
}

/// TOTP/Authenticator icon
#[component]
fn TotpIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
        </svg>
    }
}

/// Attachment/file icon
#[component]
fn AttachmentIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="18" height="18">
            <path fill="currentColor" d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5c0-1.38 1.12-2.5 2.5-2.5s2.5 1.12 2.5 2.5v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5c0 1.38 1.12 2.5 2.5 2.5s2.5-1.12 2.5-2.5V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/>
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

/// Check if an entry is expired based on expiry time
fn is_entry_expired(expiry_time: &Option<String>) -> bool {
    if let Some(time_str) = expiry_time {
        // Try to parse the timestamp and compare to now
        let now_ms = js_sys::Date::now() as i64;
        if let Some(expiry_ms) = parse_keepass_timestamp_entry(time_str) {
            return expiry_ms < now_ms;
        }
    }
    false
}

/// Format expiry time for display
fn format_expiry_time(expiry_time: &Option<String>) -> String {
    match expiry_time {
        Some(time_str) => {
            if let Some(expiry_ms) = parse_keepass_timestamp_entry(time_str) {
                let now_ms = js_sys::Date::now() as i64;
                if expiry_ms < now_ms {
                    // Already expired
                    let diff_ms = now_ms - expiry_ms;
                    format!("Expired {}", format_relative_time_entry(diff_ms))
                } else {
                    // Will expire
                    let diff_ms = expiry_ms - now_ms;
                    format!("Expires in {}", format_time_remaining(diff_ms))
                }
            } else {
                "Expires".to_string()
            }
        }
        None => "Expires".to_string(),
    }
}

/// Parse a KeePass timestamp to milliseconds since epoch
fn parse_keepass_timestamp_entry(timestamp: &str) -> Option<i64> {
    // Try ISO 8601 parsing first
    let date = js_sys::Date::parse(timestamp);
    if !date.is_nan() {
        return Some(date as i64);
    }

    // Try base64-encoded binary timestamp
    parse_base64_timestamp_entry(timestamp)
}

/// Parse a base64-encoded KeePass binary timestamp
fn parse_base64_timestamp_entry(b64: &str) -> Option<i64> {
    // This is a simplified implementation - reuse the one from history viewer
    let bytes = base64_decode(b64)?;
    if bytes.len() != 8 {
        return None;
    }

    let seconds_since_year1 = i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    const SECONDS_FROM_YEAR1_TO_UNIX: i64 = 62135596800;
    let unix_seconds = seconds_since_year1 - SECONDS_FROM_YEAR1_TO_UNIX;
    Some(unix_seconds * 1000)
}

/// Format milliseconds as relative time (for expired entries)
fn format_relative_time_entry(diff_ms: i64) -> String {
    let seconds = diff_ms / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    if days > 0 {
        format!("{} day{} ago", days, if days == 1 { "" } else { "s" })
    } else if hours > 0 {
        format!("{} hour{} ago", hours, if hours == 1 { "" } else { "s" })
    } else if minutes > 0 {
        format!("{} min{} ago", minutes, if minutes == 1 { "" } else { "s" })
    } else {
        "just now".to_string()
    }
}

/// Format milliseconds as time remaining
fn format_time_remaining(diff_ms: i64) -> String {
    let seconds = diff_ms / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;

    if days > 0 {
        format!("{} day{}", days, if days == 1 { "" } else { "s" })
    } else if hours > 0 {
        format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
    } else if minutes > 0 {
        format!("{} min{}", minutes, if minutes == 1 { "" } else { "s" })
    } else {
        "< 1 min".to_string()
    }
}

/// Format file size in human-readable format
fn format_file_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// TOTP field component
#[component]
fn TotpField(
    otp_value: String,
    copied_field: RwSignal<Option<String>>,
) -> impl IntoView {
    // Signal for the current TOTP code
    let totp_code = create_rw_signal(String::new());
    let totp_remaining = create_rw_signal(0u32);
    let totp_period = create_rw_signal(30u32);
    let totp_error = create_rw_signal(Option::<String>::None);

    let otp_for_generate = otp_value.clone();

    // Function to generate TOTP
    let generate = move || {
        match TotpConfig::parse(&otp_for_generate) {
            Ok(config) => {
                match config.generate() {
                    Ok(result) => {
                        totp_code.set(result.code);
                        totp_remaining.set(result.remaining);
                        totp_period.set(result.period);
                        totp_error.set(None);
                    }
                    Err(e) => {
                        totp_error.set(Some(e));
                    }
                }
            }
            Err(e) => {
                totp_error.set(Some(e));
            }
        }
    };

    // Generate initial code
    generate();

    // Set up interval to refresh the code
    let otp_for_interval = otp_value.clone();
    create_effect(move |_| {
        let otp = otp_for_interval.clone();
        let code_signal = totp_code;
        let remaining_signal = totp_remaining;
        let period_signal = totp_period;
        let error_signal = totp_error;

        // Update every second
        let handle = set_interval_with_handle(
            move || {
                match TotpConfig::parse(&otp) {
                    Ok(config) => {
                        match config.generate() {
                            Ok(result) => {
                                code_signal.set(result.code);
                                remaining_signal.set(result.remaining);
                                period_signal.set(result.period);
                                error_signal.set(None);
                            }
                            Err(e) => {
                                error_signal.set(Some(e));
                            }
                        }
                    }
                    Err(e) => {
                        error_signal.set(Some(e));
                    }
                }
            },
            std::time::Duration::from_secs(1),
        );

        // Cleanup on unmount
        on_cleanup(move || {
            if let Ok(h) = handle {
                h.clear();
            }
        });
    });

    // Copy handler
    let copy_totp = move |_| {
        let code = totp_code.get();
        let copied = copied_field;
        spawn_local(async move {
            if clipboard::copy_to_clipboard(&code).await.is_ok() {
                copied.set(Some("totp".to_string()));
                set_timeout(move || copied.set(None), std::time::Duration::from_secs(2));
            }
        });
    };

    view! {
        <div class="field-group totp-field">
            <label>"TOTP"</label>
            <div class="field-value-row">
                {move || {
                    if let Some(error) = totp_error.get() {
                        view! {
                            <span class="totp-error">{error}</span>
                        }.into_view()
                    } else {
                        let code = totp_code.get();
                        let remaining = totp_remaining.get();
                        let period = totp_period.get();
                        let progress = (remaining as f64 / period as f64) * 100.0;

                        view! {
                            <div class="totp-display">
                                <span class="totp-code">{code}</span>
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
                                            stroke-dasharray=move || format!("{}, 100", progress)
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
                    class:copied=move || copied_field.get() == Some("totp".to_string())
                    on:click=copy_totp
                    title="Copy TOTP code"
                >
                    <CopyIcon />
                </button>
            </div>
        </div>
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

/// History viewer dialog
#[component]
fn HistoryViewer(
    history: Vec<HistoryEntryInfo>,
    entry_title: String,
    on_close: impl Fn() + Clone + 'static,
) -> impl IntoView {
    let selected_index = create_rw_signal(Option::<usize>::None);
    let show_password = create_rw_signal(false);

    // Reverse history so newest is first
    let history_reversed: Vec<(usize, HistoryEntryInfo)> = history
        .into_iter()
        .enumerate()
        .rev()
        .collect();

    let on_close_overlay = on_close.clone();
    let on_close_button = on_close;

    view! {
        <div class="dialog-overlay" on:click=move |_| on_close_overlay()>
            <div class="dialog history-dialog" on:click=|e| e.stop_propagation()>
                <div class="dialog-header">
                    <h2>"History: " {entry_title}</h2>
                    <button class="dialog-close" on:click=move |_| on_close_button() title="Close">
                        <svg viewBox="0 0 24 24" width="20" height="20">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>

                <div class="dialog-body">
                    <div class="history-list">
                        {history_reversed.iter().map(|(idx, entry)| {
                            let idx = *idx;
                            let timestamp = entry.last_modification_time.clone().unwrap_or_else(|| "Unknown date".to_string());
                            let title = entry.title.clone();
                            let (relative, rfc3339) = format_timestamp_relative(&timestamp);

                            view! {
                                <div
                                    class="history-item"
                                    class:selected=move || selected_index.get() == Some(idx)
                                    on:click=move |_| selected_index.set(Some(idx))
                                >
                                    <div class="history-item-date" title=rfc3339>{relative}</div>
                                    <div class="history-item-title">{title}</div>
                                </div>
                            }
                        }).collect_view()}
                    </div>

                    <div class="history-detail">
                        {move || {
                            match selected_index.get() {
                                None => view! {
                                    <div class="history-no-selection">
                                        "Select a version to view details"
                                    </div>
                                }.into_view(),
                                Some(idx) => {
                                    // Find the entry at this index
                                    let entry = history_reversed.iter()
                                        .find(|(i, _)| *i == idx)
                                        .map(|(_, e)| e.clone());

                                    match entry {
                                        None => view! {
                                            <div class="history-no-selection">"Version not found"</div>
                                        }.into_view(),
                                        Some(hist_entry) => {
                                            let password_for_display = hist_entry.password.clone().unwrap_or_default();

                                            view! {
                                                <div class="history-entry-detail">
                                                    <div class="history-field">
                                                        <label>"Title"</label>
                                                        <div class="history-field-value">{hist_entry.title}</div>
                                                    </div>
                                                    <div class="history-field">
                                                        <label>"Username"</label>
                                                        <div class="history-field-value">{hist_entry.username}</div>
                                                    </div>
                                                    <div class="history-field">
                                                        <label>"Password"</label>
                                                        <div class="history-field-value password-field">
                                                            {move || {
                                                                if show_password.get() {
                                                                    password_for_display.clone()
                                                                } else {
                                                                    "••••••••".to_string()
                                                                }
                                                            }}
                                                            <button
                                                                class="btn-icon-small"
                                                                on:click=move |_| show_password.update(|v| *v = !*v)
                                                                title=move || if show_password.get() { "Hide" } else { "Show" }
                                                            >
                                                                {move || if show_password.get() {
                                                                    view! { <EyeOffIcon /> }.into_view()
                                                                } else {
                                                                    view! { <EyeIcon /> }.into_view()
                                                                }}
                                                            </button>
                                                        </div>
                                                    </div>
                                                    <div class="history-field">
                                                        <label>"URL"</label>
                                                        <div class="history-field-value">{hist_entry.url}</div>
                                                    </div>
                                                    <div class="history-field">
                                                        <label>"Notes"</label>
                                                        <div class="history-field-value notes">{hist_entry.notes}</div>
                                                    </div>
                                                    <div class="history-field">
                                                        <label>"Modified"</label>
                                                        <div class="history-field-value">
                                                            {hist_entry.last_modification_time.unwrap_or_else(|| "Unknown".to_string())}
                                                        </div>
                                                    </div>
                                                </div>
                                            }.into_view()
                                        }
                                    }
                                }
                            }
                        }}
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Format a KeePass timestamp as relative time (e.g., "2h ago") and RFC 3339
/// Returns (relative_string, rfc3339_string)
fn format_timestamp_relative(timestamp: &str) -> (String, String) {
    // KeePass stores timestamps either as:
    // 1. ISO format like "2024-01-15T10:30:00Z"
    // 2. Base64-encoded 8-byte binary (seconds since 0001-01-01)

    // Handle empty or invalid timestamps gracefully
    if timestamp.is_empty() || timestamp == "Unknown date" {
        return ("Unknown".to_string(), "Unknown".to_string());
    }

    // Try to parse the timestamp
    match parse_keepass_timestamp(timestamp) {
        Some(epoch_ms) => {
            let now_ms = js_sys::Date::now() as i64;
            let diff_ms = now_ms - epoch_ms;

            let relative = format_relative_time(diff_ms);

            // Format as RFC 3339
            let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(epoch_ms as f64));
            let rfc3339 = date.to_iso_string().as_string().unwrap_or_else(|| timestamp.to_string());

            (relative, rfc3339)
        }
        None => {
            // Fallback for unparseable timestamps - show raw value
            (timestamp.to_string(), timestamp.to_string())
        }
    }
}

/// Parse a KeePass timestamp (ISO 8601 or base64-encoded binary) to milliseconds since epoch
fn parse_keepass_timestamp(timestamp: &str) -> Option<i64> {
    // First try ISO 8601 parsing
    let date = js_sys::Date::parse(timestamp);
    if !date.is_nan() {
        return Some(date as i64);
    }

    // Try base64-encoded binary timestamp
    // KeePass uses 8 bytes representing seconds since 0001-01-01 00:00:00 UTC
    if let Some(epoch_ms) = parse_base64_timestamp(timestamp) {
        return Some(epoch_ms);
    }

    None
}

/// Parse a base64-encoded KeePass binary timestamp
/// KeePass stores timestamps as 8-byte little-endian seconds since 0001-01-01
fn parse_base64_timestamp(b64: &str) -> Option<i64> {
    // Decode base64
    let bytes = base64_decode(b64)?;
    if bytes.len() != 8 {
        return None;
    }

    // Read as little-endian i64 (seconds since 0001-01-01)
    let seconds_since_year1 = i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    // Convert to Unix epoch (seconds since 1970-01-01)
    // Difference between 0001-01-01 and 1970-01-01 is 62135596800 seconds
    const SECONDS_FROM_YEAR1_TO_UNIX: i64 = 62135596800;
    let unix_seconds = seconds_since_year1 - SECONDS_FROM_YEAR1_TO_UNIX;

    // Convert to milliseconds
    Some(unix_seconds * 1000)
}

/// Simple base64 decoder
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_val(c: u8) -> Option<u8> {
        ALPHABET.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::new();
    let bytes = input.as_bytes();

    for chunk in bytes.chunks(4) {
        let mut buf = 0u32;
        let mut valid_chars = 0;

        for &c in chunk {
            if let Some(val) = char_to_val(c) {
                buf = (buf << 6) | (val as u32);
                valid_chars += 1;
            }
        }

        // Pad the buffer if we have fewer than 4 characters
        buf <<= 6 * (4 - valid_chars);

        match valid_chars {
            4 => {
                output.push((buf >> 16) as u8);
                output.push((buf >> 8) as u8);
                output.push(buf as u8);
            }
            3 => {
                output.push((buf >> 16) as u8);
                output.push((buf >> 8) as u8);
            }
            2 => {
                output.push((buf >> 16) as u8);
            }
            _ => return None,
        }
    }

    Some(output)
}

/// Format milliseconds difference as human-readable relative time
fn format_relative_time(diff_ms: i64) -> String {
    let seconds = diff_ms / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;
    let days = hours / 24;
    let weeks = days / 7;
    let months = days / 30;
    let years = days / 365;

    if seconds < 0 {
        "in the future".to_string()
    } else if seconds < 60 {
        "just now".to_string()
    } else if minutes < 60 {
        if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        }
    } else if hours < 24 {
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if days < 7 {
        if days == 1 {
            "yesterday".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if weeks < 4 {
        if weeks == 1 {
            "1 week ago".to_string()
        } else {
            format!("{} weeks ago", weeks)
        }
    } else if months < 12 {
        if months == 1 {
            "1 month ago".to_string()
        } else {
            format!("{} months ago", months)
        }
    } else if years == 1 {
        "1 year ago".to_string()
    } else {
        format!("{} years ago", years)
    }
}
