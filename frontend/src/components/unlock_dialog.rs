//! Unlock dialog component for entering the master password

use leptos::*;
use web_sys::KeyboardEvent;

use crate::state::{AppState, AppView};

/// Unlock dialog component
#[component]
pub fn UnlockDialog() -> impl IntoView {
    let state = expect_context::<AppState>();

    let password = create_rw_signal(String::new());
    let error = create_rw_signal(Option::<String>::None);
    let is_unlocking = create_rw_signal(false);
    let show_password = create_rw_signal(false);

    let password_input_ref = create_node_ref::<leptos::html::Input>();

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
