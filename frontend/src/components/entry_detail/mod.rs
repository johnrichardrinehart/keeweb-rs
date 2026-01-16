//! Entry detail/editor component

use leptos::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::components::password_generator::PasswordGenerator;
use crate::state::AppState;
use crate::utils::clipboard;

mod totp;
use totp::TotpConfig;

/// Entry detail component
#[component]
pub fn EntryDetail() -> impl IntoView {
    let state = expect_context::<AppState>();

    let show_password = create_rw_signal(false);
    let show_generator = create_rw_signal(false);
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
                                show_password=show_password
                                show_generator=show_generator
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
    show_password: RwSignal<bool>,
    show_generator: RwSignal<bool>,
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

    view! {
        <div class="entry-detail-header">
            <h2>{title}</h2>
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
        </div>

        <div class="entry-detail-footer">
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
