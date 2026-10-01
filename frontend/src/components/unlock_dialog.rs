//! Unlock dialog: master password, optional key file and fingerprint unlock

use leptos::spawn_local;
use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::components::icons::{Icon, UiIcon};
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
                    <button
                        type="button"
                        class="btn-icon dialog-close"
                        on:click=on_cancel
                        title="Close"
                        aria-label="Close unlock dialog"
                    >
                        <UiIcon icon=Icon::X />
                    </button>
                </div>

                <div class="dialog-body">
                    <Show when=move || record.with(Option::is_some)>
                        <button
                            type="button"
                            class="btn btn-primary btn-lg btn-fingerprint"
                            on:click=unlock_with_fingerprint
                            disabled=move || is_unlocking.get()
                        >
                            <UiIcon icon=Icon::Fingerprint size=20 />
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
                                    class="btn-icon btn-icon-sm password-toggle"
                                    on:click=toggle_visibility
                                    title=move || if show_password.get() { "Hide password" } else { "Show password" }
                                    aria-label=move || if show_password.get() { "Hide password" } else { "Show password" }
                                >
                                    {move || {
                                        let icon = if show_password.get() { Icon::EyeOff } else { Icon::Eye };
                                        view! { <UiIcon icon=icon /> }
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
                                    <UiIcon icon=Icon::KeyRound size=16 />
                                    <span class="key-file-name">
                                        {move || key_file_name.get().unwrap_or_else(|| "Choose key file…".to_string())}
                                    </span>
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
                                        <UiIcon icon=Icon::X />
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
                    <button type="button" class="btn btn-secondary btn-lg" on:click=on_cancel disabled=move || is_unlocking.get()>
                        "Cancel"
                    </button>
                    <button
                        type="button"
                        class="btn btn-primary btn-lg"
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
