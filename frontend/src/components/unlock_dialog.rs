//! Unlock dialog: master password, optional key file and fingerprint unlock

use leptos::spawn_local;
use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::helper_client;
use crate::quick_unlock::{self, Support};
use crate::state::{self, AppState, HelperStatus, KeyFile};
use crate::utils::files;

/// Unlock dialog component
#[component]
pub fn UnlockDialog() -> impl IntoView {
    let state = expect_context::<AppState>();
    // The dialog unmounts whenever the pending vault changes.
    let vault = state
        .pending
        .with_untracked(|pending| pending.as_ref().map(|pending| pending.source.vault_key()));
    let vault_name = move || {
        state
            .pending
            .with(|pending| {
                pending
                    .as_ref()
                    .map(|pending| pending.source.name().to_string())
            })
            .unwrap_or_default()
    };

    let password = create_rw_signal(String::new());
    let error = create_rw_signal(Option::<String>::None);
    let is_unlocking = create_rw_signal(false);
    let show_password = create_rw_signal(false);
    // Contents stay out of signals; only the name is displayed.
    let key_file = store_value(Option::<KeyFile>::None);
    let key_file_name = create_rw_signal(Option::<String>::None);
    let key_file_hint = vault.as_deref().and_then(state::key_file_hint);
    let record = create_rw_signal(Option::<quick_unlock::Record>::None);
    let support = create_rw_signal(Support::Unavailable);
    let enroll = create_rw_signal(false);

    let password_input_ref = create_node_ref::<leptos::html::Input>();
    let key_file_input_ref = create_node_ref::<leptos::html::Input>();

    if let Some(vault) = vault {
        spawn_local(async move {
            record.set(quick_unlock::load(&vault).await);
            support.set(quick_unlock::support().await);
        });
    }

    // Focus password input on mount
    create_effect(move |_| {
        if let Some(input) = password_input_ref.get() {
            let _ = input.focus();
        }
    });

    // Heartbeat: check helper availability every 1 second
    let heartbeat_interval: StoredValue<Option<i32>> = store_value(None);

    create_effect(move |_| {
        // Start heartbeat interval
        let window = web_sys::window().expect("no window");
        let closure: Closure<dyn Fn()> = Closure::new(move || {
            spawn_local(async move {
                let status = match helper_client::check_helper_available_fresh().await {
                    Ok(true) => HelperStatus::Connected,
                    Ok(false) | Err(_) => HelperStatus::Unavailable,
                };
                state.helper_status.set(status);
            });
        });

        let interval_id = window
            .set_interval_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                1000, // 1 second
            )
            .expect("set_interval failed");

        closure.forget();
        heartbeat_interval.set_value(Some(interval_id));
    });

    // Clean up heartbeat on unmount
    on_cleanup(move || {
        if let Some(interval_id) = heartbeat_interval.get_value() {
            if let Some(window) = web_sys::window() {
                window.clear_interval_with_handle(interval_id);
            }
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

    let can_unlock = move || {
        !is_unlocking.get()
            && (!password.with(String::is_empty) || key_file_name.with(Option::is_some))
    };

    // Key derivation runs off the main thread or in the native helper.
    let try_unlock = move || {
        if !can_unlock() {
            return;
        }
        is_unlocking.set(true);
        error.set(None);

        // A copy, so a wrong password can be retried without choosing the file again.
        let chosen = key_file.with_value(Clone::clone);
        state.unlock(
            Zeroizing::new(password.get_untracked()),
            chosen,
            enroll.get_untracked(),
            is_unlocking,
            error,
        );

        password.set(String::new());
    };

    let unlock_with_fingerprint = move |_| {
        let Some(record) = record.get_untracked() else {
            return;
        };
        is_unlocking.set(true);
        error.set(None);
        state.unlock_with_fingerprint(record, is_unlocking, error);
    };

    let choose_key_file = move |_| {
        if let Some(input) = key_file_input_ref.get_untracked() {
            input.click();
        }
    };
    let on_key_file = move |event: web_sys::Event| {
        let Some(file) = files::take_input_files(&event).into_iter().next() else {
            return;
        };
        spawn_local(async move {
            match files::read_secret_file(&file).await {
                Ok(data) => {
                    let name = file.name();
                    key_file.set_value(Some(KeyFile {
                        name: name.clone(),
                        data,
                    }));
                    key_file_name.set(Some(name));
                    error.set(None);
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };
    let clear_key_file = move |_| {
        key_file.set_value(None);
        key_file_name.set(None);
    };

    // Handle form submit
    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        try_unlock();
    };

    // Handle cancel
    let on_cancel = move |_| {
        state.pending.set(None);
    };

    // Toggle password visibility
    let toggle_visibility = move |_| {
        show_password.update(|v| *v = !*v);
    };

    view! {
        <div class="dialog-overlay">
            <div
                class="dialog unlock-dialog"
                role="dialog"
                aria-modal="true"
                aria-labelledby="unlock-title"
            >
                <div class="dialog-header">
                    <div>
                        <h2 id="unlock-title">"Unlock vault"</h2>
                        <p class="database-file-name">{vault_name}</p>
                    </div>
                    <button class="dialog-close" on:click=on_cancel aria-label="Close unlock dialog">
                        <svg viewBox="0 0 24 24" width="20" height="20">
                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                        </svg>
                    </button>
                </div>

                <div class="dialog-body">
                    <Show when=move || record.with(Option::is_some)>
                        <button
                            type="button"
                            class="btn btn-primary btn-fingerprint"
                            on:click=unlock_with_fingerprint
                            disabled=move || is_unlocking.get()
                        >
                            <FingerprintIcon />
                            "Unlock with fingerprint"
                        </button>
                        <p class="unlock-divider"><span>"or use the master password"</span></p>
                    </Show>

                    <form on:submit=on_submit>
                        <div class="form-group">
                            <label for="password">"Master Password"</label>
                            <div class="password-input-wrapper">
                                <input
                                    type="password"
                                    id="password"
                                    class="form-input"
                                    autocomplete="current-password"
                                    placeholder=move || key_file_name.with(Option::is_some).then_some("Optional with a key file")
                                    node_ref=password_input_ref
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
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

                        <div class="form-group key-file-group">
                            <span class="key-file-label">"Key file"</span>
                            <div class="key-file-row">
                                <button
                                    type="button"
                                    class="btn btn-secondary key-file-button"
                                    on:click=choose_key_file
                                    disabled=move || is_unlocking.get()
                                >
                                    {move || key_file_name.get().unwrap_or_else(|| "Choose key file…".to_string())}
                                </button>
                                <Show when=move || key_file_name.with(Option::is_some)>
                                    <button
                                        type="button"
                                        class="btn-icon"
                                        on:click=clear_key_file
                                        disabled=move || is_unlocking.get()
                                        title="Remove key file"
                                        aria-label="Remove key file"
                                    >
                                        <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
                                            <path fill="currentColor" d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                                        </svg>
                                    </button>
                                </Show>
                            </div>
                            {key_file_hint.map(|hint| view! {
                                <Show when=move || key_file_name.with(Option::is_none)>
                                    <p class="section-hint">{format!("Last used on this device: {hint}")}</p>
                                </Show>
                            })}
                            <input
                                type="file"
                                class="visually-hidden"
                                tabindex="-1"
                                aria-hidden="true"
                                node_ref=key_file_input_ref
                                on:change=on_key_file
                            />
                        </div>

                        <Show when=move || support.get() != Support::Unavailable && record.with(Option::is_none)>
                            <label class="checkbox-label fingerprint-option">
                                <input
                                    type="checkbox"
                                    prop:checked=move || enroll.get()
                                    on:change=move |ev| enroll.set(event_target_checked(&ev))
                                    disabled=move || is_unlocking.get()
                                />
                                "Unlock with fingerprint on this device"
                            </label>
                        </Show>

                        <Show when=move || error.get().is_some()>
                            <div class="error-message" role="alert">
                                {move || error.get().unwrap_or_default()}
                            </div>
                        </Show>
                    </form>

                    <Show when=move || state.helper_status.get() != HelperStatus::Connected>
                        <p class="unlock-note">"Unlocking in the browser can take a while."</p>
                    </Show>
                </div>

                <div class="dialog-footer">
                    <button class="btn btn-secondary" on:click=on_cancel disabled=move || is_unlocking.get()>
                        "Cancel"
                    </button>
                    <button
                        class="btn btn-primary"
                        on:click=move |_| try_unlock()
                        disabled=move || !can_unlock()
                    >
                        {move || if is_unlocking.get() { "Unlocking..." } else { "Unlock" }}
                    </button>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn FingerprintIcon() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
            <path fill="currentColor" d="M17.81 4.47c-.08 0-.16-.02-.23-.06C15.66 3.42 14 3 12.01 3c-1.98 0-3.86.47-5.57 1.41-.24.13-.54.04-.68-.2-.13-.24-.04-.55.2-.68C7.82 2.52 9.86 2 12.01 2c2.13 0 3.99.47 6.03 1.52.25.13.34.43.21.67-.09.18-.26.28-.44.28zM3.5 9.72c-.1 0-.2-.03-.29-.09-.23-.16-.28-.47-.12-.7.99-1.4 2.25-2.5 3.75-3.27C9.98 4.04 14 4.03 17.15 5.65c1.5.77 2.76 1.86 3.75 3.25.16.22.11.54-.12.7-.23.16-.54.11-.7-.12-.9-1.26-2.04-2.25-3.39-2.94-2.87-1.47-6.54-1.47-9.4.01-1.36.7-2.5 1.7-3.4 2.96-.08.14-.23.21-.39.21zm6.25 12.07c-.13 0-.26-.05-.35-.15-.87-.87-1.34-1.43-2.01-2.64-.69-1.23-1.05-2.73-1.05-4.34 0-2.97 2.54-5.39 5.66-5.39s5.66 2.42 5.66 5.39c0 .28-.22.5-.5.5s-.5-.22-.5-.5c0-2.42-2.09-4.39-4.66-4.39-2.57 0-4.66 1.97-4.66 4.39 0 1.44.32 2.77.93 3.85.64 1.15 1.08 1.64 1.85 2.42.19.2.19.51 0 .71-.11.1-.24.15-.37.15zm7.17-1.85c-1.19 0-2.24-.3-3.1-.89-1.49-1.01-2.38-2.65-2.38-4.39 0-.28.22-.5.5-.5s.5.22.5.5c0 1.41.72 2.74 1.94 3.56.71.48 1.54.71 2.54.71.24 0 .64-.03 1.04-.1.27-.05.53.13.58.41.05.27-.13.53-.41.58-.57.11-1.07.12-1.21.12zM14.91 22c-.04 0-.09-.01-.13-.02-1.59-.44-2.63-1.03-3.72-2.1-1.4-1.39-2.17-3.24-2.17-5.22 0-1.62 1.38-2.94 3.08-2.94 1.7 0 3.08 1.32 3.08 2.94 0 1.07.93 1.94 2.08 1.94s2.08-.87 2.08-1.94c0-3.77-3.25-6.83-7.25-6.83-2.84 0-5.44 1.58-6.61 4.03-.39.81-.59 1.76-.59 2.8 0 .78.07 2.01.67 3.61.1.26-.03.55-.29.64-.26.1-.55-.04-.64-.29-.49-1.31-.73-2.61-.73-3.96 0-1.2.23-2.29.68-3.24 1.33-2.79 4.28-4.6 7.51-4.6 4.55 0 8.25 3.51 8.25 7.83 0 1.62-1.38 2.94-3.08 2.94s-3.08-1.32-3.08-2.94c0-1.07-.93-1.94-2.08-1.94s-2.08.87-2.08 1.94c0 1.71.66 3.31 1.87 4.51.95.94 1.86 1.46 3.27 1.85.27.07.42.35.35.61-.05.23-.26.38-.47.38z"/>
        </svg>
    }
}
