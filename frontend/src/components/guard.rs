//! Unsaved-change protection: the browser `beforeunload` prompt, the lock guard, the
//! unsaved-changes list and the merge conflict report.

use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use crate::components::dialog::Dialog;
use crate::state::AppState;

/// Registers a `beforeunload` handler only while some unlocked vault has unsaved
/// changes, so the browser shows its generic leave-page prompt and clean pages stay
/// eligible for the back/forward cache.
pub fn install_unload_guard(state: AppState) {
    let handler: Closure<dyn Fn(web_sys::BeforeUnloadEvent)> =
        Closure::new(|event: web_sys::BeforeUnloadEvent| {
            event.prevent_default();
            // Older browsers only prompt when returnValue is set.
            event.set_return_value("");
        });
    let handler = store_value(handler);
    let installed = store_value(false);

    create_effect(move |_| {
        let dirty = state.any_dirty();
        if dirty == installed.get_value() {
            return;
        }
        let Some(window) = web_sys::window() else {
            return;
        };
        handler.with_value(|handler| {
            let callback = handler.as_ref().unchecked_ref();
            if dirty {
                let _ = window.add_event_listener_with_callback("beforeunload", callback);
            } else {
                let _ = window.remove_event_listener_with_callback("beforeunload", callback);
            }
        });
        installed.set_value(dirty);
    });
}

/// Ctrl+S / Cmd+S saves the vault on screen.
pub fn install_save_shortcut(state: AppState) {
    let handler: Closure<dyn Fn(web_sys::KeyboardEvent)> =
        Closure::new(move |event: web_sys::KeyboardEvent| {
            if !(event.ctrl_key() || event.meta_key()) || !event.key().eq_ignore_ascii_case("s") {
                return;
            }
            if state.active.get_untracked().is_none() {
                return;
            }
            event.prevent_default();
            if state.changes.with_untracked(|changes| !changes.is_empty())
                && !state.saving.get_untracked()
            {
                state.save_in_background();
            }
        });
    if let Some(window) = web_sys::window() {
        let _ =
            window.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
    }
    // The shortcut lives as long as the page.
    handler.forget();
}

/// Ordered list of unsaved change summaries.
#[component]
pub fn ChangeList() -> impl IntoView {
    let state = expect_context::<AppState>();
    view! {
        <ol class="change-list">
            {move || state.changes.get().into_iter().map(|summary| view! {
                <li>{summary}</li>
            }).collect_view()}
        </ol>
    }
}

/// Asks what to do with unsaved changes before locking the vault on screen.
#[component]
pub fn LockGuard() -> impl IntoView {
    let state = expect_context::<AppState>();
    let error = create_rw_signal(Option::<String>::None);

    let cancel = move || {
        error.set(None);
        state.lock_requested.set(false);
    };
    let discard = move |_| {
        error.set(None);
        state.lock_requested.set(false);
        if let Some(id) = state.active.get_untracked() {
            state.lock_session(id);
        }
    };
    let save_and_lock = move |_| {
        let Some(id) = state.active.get_untracked() else {
            return;
        };
        error.set(None);
        spawn_local(async move {
            match state.save_session(id).await {
                Ok(()) => {
                    state.lock_requested.set(false);
                    state.lock_session(id);
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    view! {
        <Show when=move || state.lock_requested.get()>
            <Dialog
                title="Lock with unsaved changes?"
                class="guard-dialog"
                on_close=move |_| cancel()
            >
                <div class="dialog-body">
                    <p class="dialog-lead">
                        {move || {
                            let count = state.changes.with(Vec::len);
                            format!(
                                "{count} change{} will be lost unless you save them.",
                                if count == 1 { "" } else { "s" }
                            )
                        }}
                    </p>
                    <ChangeList />
                    <Show when=move || error.get().is_some()>
                        <div class="error-message" role="alert">
                            {move || format!("Save failed: {}", error.get().unwrap_or_default())}
                        </div>
                    </Show>
                </div>
                <div class="dialog-footer">
                    <button class="btn btn-secondary" on:click=move |_| cancel()>"Cancel"</button>
                    <button
                        class="btn btn-danger"
                        on:click=discard
                        disabled=move || state.saving.get()
                    >
                        "Discard changes"
                    </button>
                    <button
                        class="btn btn-primary"
                        on:click=save_and_lock
                        disabled=move || state.saving.get()
                    >
                        {move || if state.saving.get() { "Saving…" } else { "Save" }}
                    </button>
                </div>
            </Dialog>
        </Show>
    }
}

/// The unsaved changes, opened from the header.
#[component]
pub fn ChangesDialog() -> impl IntoView {
    let state = expect_context::<AppState>();
    view! {
        <Show when=move || state.show_changes.get()>
            <Dialog title="Unsaved changes" on_close=move |_| state.show_changes.set(false)>
                <div class="dialog-body">
                    <Show
                        when=move || state.is_dirty()
                        fallback=|| view! { <p class="dialog-lead">"Everything is saved."</p> }
                    >
                        <ChangeList />
                    </Show>
                </div>
                <div class="dialog-footer">
                    <button class="btn btn-secondary" on:click=move |_| state.show_changes.set(false)>
                        "Close"
                    </button>
                    <button
                        class="btn btn-primary"
                        disabled=move || !state.is_dirty() || state.saving.get()
                        on:click=move |_| {
                            state.show_changes.set(false);
                            state.save_in_background();
                        }
                    >
                        "Save"
                    </button>
                </div>
            </Dialog>
        </Show>
    }
}

/// Items edited both here and elsewhere, reported after a merging save.
#[component]
pub fn MergeConflicts() -> impl IntoView {
    let state = expect_context::<AppState>();
    let close = move || state.merge_conflicts.set(Vec::new());
    view! {
        <Show when=move || state.merge_conflicts.with(|conflicts| !conflicts.is_empty())>
            <Dialog title="Merged with changes from elsewhere" on_close=move |_| close()>
                <div class="dialog-body">
                    <p class="dialog-lead">
                        "These items were changed both here and in another copy. The newer version was kept; the other one is in the item's history."
                    </p>
                    <ul class="change-list">
                        {move || state.merge_conflicts.get().into_iter().map(|title| view! {
                            <li>{title}</li>
                        }).collect_view()}
                    </ul>
                </div>
                <div class="dialog-footer">
                    <button class="btn btn-primary" on:click=move |_| close()>"OK"</button>
                </div>
            </Dialog>
        </Show>
    }
}
