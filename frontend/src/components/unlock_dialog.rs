//! Unlock dialog component for entering the master password

use leptos::*;
use leptos::spawn_local;
use web_sys::KeyboardEvent;

use crate::helper_client;
use crate::state::{AppState, AppView};

/// Unlock dialog component
#[component]
pub fn UnlockDialog() -> impl IntoView {
    let state = expect_context::<AppState>();

    let password = create_rw_signal(String::new());
    let error = create_rw_signal(Option::<String>::None);
    let is_unlocking = create_rw_signal(false);
    let show_password = create_rw_signal(false);
    let show_helper_config = create_rw_signal(false);

    // Initialize helper URL from current config or default
    let initial_url = helper_client::get_helper_url()
        .unwrap_or_else(|| helper_client::DEFAULT_HELPER_URL.to_string());
    let helper_url = create_rw_signal(initial_url);
    let is_available = helper_client::is_helper_available();
    log::info!("UnlockDialog init: is_helper_available() = {}", is_available);
    let helper_enabled = create_rw_signal(is_available);

    let password_input_ref = create_node_ref::<leptos::html::Input>();

    // Configure helper when URL changes and is enabled
    let apply_helper_config = move || {
        let url = helper_url.get();
        if !url.is_empty() {
            helper_client::configure_helper(&url);
            // Spawn async task to verify connection
            spawn_local(async move {
                match helper_client::check_helper_available().await {
                    Ok(available) => {
                        helper_enabled.set(available);
                        if !available {
                            log::warn!("Helper server at {} is not reachable", url);
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to check helper availability: {}", e);
                        helper_enabled.set(false);
                    }
                }
            });
        }
    };

    // Disable helper
    let disable_helper = move || {
        helper_client::disable_helper();
        helper_enabled.set(false);
    };

    // Focus password input on mount
    create_effect(move |_| {
        if let Some(input) = password_input_ref.get() {
            let _ = input.focus();
        }
    });

    // Update input type when show_password changes
    create_effect(move |_| {
        let show = show_password.get();
        if let Some(input) = password_input_ref.get() {
            let input_type = if show { "text" } else { "password" };
            let _ = input.set_attribute("type", input_type);
        }
    });

    // Handle unlock attempt using Web Worker (non-blocking)
    let try_unlock = move || {
        is_unlocking.set(true);
        error.set(None);

        let pwd = password.get();

        // Use async worker-based unlock to avoid blocking UI
        // Pass the signals so the worker callback can update them directly
        state.unlock_database_async(&pwd, is_unlocking, error);

        // Clear password field immediately (it's already been sent to worker)
        password.set(String::new());
    };

    // Handle form submit
    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        try_unlock();
    };

    // Handle key press (Enter to submit)
    let on_keydown = move |ev: KeyboardEvent| {
        if ev.key() == "Enter" {
            try_unlock();
        }
    };

    // Handle cancel
    let on_cancel = move |_| {
        state.pending_file_data.set(None);
        state.database_source.set(None);
        state.current_view.set(AppView::FilePicker);
    };

    // Toggle password visibility
    let toggle_visibility = move |_| {
        show_password.update(|v| *v = !*v);
    };

    view! {
        <div class="dialog-overlay">
            <div class="dialog unlock-dialog">
                <div class="dialog-header">
                    <h2>"Unlock Database"</h2>
                    <button class="dialog-close" on:click=on_cancel>
                        <svg viewBox="0 0 24 24" width="20" height="20">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>

                <div class="dialog-body">
                    <p class="database-file-name">
                        {move || state.database_name.get()}
                    </p>

                    <form on:submit=on_submit>
                        <div class="form-group">
                            <label for="password">"Master Password"</label>
                            <div class="password-input-wrapper">
                                <input
                                    type="password"
                                    id="password"
                                    class="form-input"
                                    placeholder="Enter your master password"
                                    autocomplete="current-password"
                                    node_ref=password_input_ref
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
                                    on:keydown=on_keydown
                                    disabled=move || is_unlocking.get()
                                />
                                <button
                                    type="button"
                                    class="password-toggle"
                                    on:click=toggle_visibility
                                    title=move || if show_password.get() { "Hide password" } else { "Show password" }
                                >
                                    {move || if show_password.get() {
                                        view! {
                                            <svg viewBox="0 0 24 24" width="20" height="20">
                                                <path fill="currentColor" d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z"/>
                                            </svg>
                                        }.into_view()
                                    } else {
                                        view! {
                                            <svg viewBox="0 0 24 24" width="20" height="20">
                                                <path fill="currentColor" d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
                                            </svg>
                                        }.into_view()
                                    }}
                                </button>
                            </div>
                        </div>

                        <Show when=move || error.get().is_some()>
                            <div class="error-message">
                                {move || error.get().unwrap_or_default()}
                            </div>
                        </Show>
                    </form>

                    // Helper server configuration section
                    <div class="helper-config-section">
                        <button
                            type="button"
                            class="helper-config-toggle"
                            on:click=move |_| show_helper_config.update(|v| *v = !*v)
                        >
                            <svg viewBox="0 0 24 24" width="16" height="16" style="margin-right: 4px;">
                                <path fill="currentColor" d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>
                            </svg>
                            {move || {
                                if helper_enabled.get() {
                                    "Unlock helper: connected"
                                } else if show_helper_config.get() {
                                    "Hide unlock helper settings"
                                } else {
                                    "Configure unlock helper (optional)"
                                }
                            }}
                            {move || if helper_enabled.get() {
                                view! {
                                    <span class="helper-status-indicator helper-status-connected" title="Helper server connected">
                                        " ✓"
                                    </span>
                                }.into_view()
                            } else {
                                view! { <span></span> }.into_view()
                            }}
                        </button>

                        <Show when=move || show_helper_config.get()>
                            <div class="helper-config-panel">
                                <p class="helper-description">
                                    "For databases with high-memory Argon2 settings (1GB+), browser unlock can take ~30 seconds. "
                                    "Running the keeweb-server locally provides native-speed unlock (~4s)."
                                </p>
                                <div class="form-group">
                                    <label for="helper-url">"Helper Server URL"</label>
                                    <div class="helper-url-input-wrapper">
                                        <input
                                            type="text"
                                            id="helper-url"
                                            class="form-input"
                                            placeholder="http://127.0.0.1:8081"
                                            prop:value=move || helper_url.get()
                                            on:input=move |ev| helper_url.set(event_target_value(&ev))
                                            disabled=move || helper_enabled.get()
                                        />
                                        <Show
                                            when=move || helper_enabled.get()
                                            fallback=move || view! {
                                                <button
                                                    type="button"
                                                    class="btn btn-small"
                                                    on:click=move |_| apply_helper_config()
                                                >
                                                    "Connect"
                                                </button>
                                            }
                                        >
                                            <button
                                                type="button"
                                                class="btn btn-small btn-danger"
                                                on:click=move |_| disable_helper()
                                            >
                                                "Disable"
                                            </button>
                                        </Show>
                                    </div>
                                </div>
                                <Show when=move || helper_enabled.get()>
                                    <p class="helper-status helper-status-enabled">
                                        "Helper connected - high-memory databases will use native Argon2"
                                    </p>
                                </Show>
                            </div>
                        </Show>
                    </div>
                </div>

                <div class="dialog-footer">
                    <button class="btn btn-secondary" on:click=on_cancel disabled=move || is_unlocking.get()>
                        "Cancel"
                    </button>
                    <button
                        class="btn btn-primary"
                        on:click=move |_| try_unlock()
                        disabled=move || is_unlocking.get() || password.get().is_empty()
                    >
                        {move || if is_unlocking.get() { "Unlocking..." } else { "Unlock" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
