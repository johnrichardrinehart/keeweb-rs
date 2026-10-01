//! File picker component with drag-and-drop support

use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{DragEvent, Event, File, HtmlInputElement};

use crate::model::format_size;
use crate::server::{self, StoredFile};
use crate::state::{AppState, DatabaseSource, HelperStatus};
use crate::utils::files;

/// File picker component
#[component]
pub fn FilePicker() -> impl IntoView {
    let state = expect_context::<AppState>();
    let is_dragging = create_rw_signal(false);
    let file_input_ref = create_node_ref::<leptos::html::Input>();
    let stored_files = create_rw_signal(Vec::<StoredFile>::new());
    let storage_loaded = create_rw_signal(!server::storage_enabled());

    if server::storage_enabled() {
        spawn_local(async move {
            match server::list_files().await {
                Ok(files) => stored_files.set(files),
                Err(error) => state.error_message.set(Some(error)),
            }
            storage_loaded.set(true);
        });
    }

    let on_drag_over = move |event: DragEvent| {
        event.prevent_default();
        is_dragging.set(true);
    };
    let on_drag_leave = move |event: DragEvent| {
        event.prevent_default();
        is_dragging.set(false);
    };
    let on_drop = move |event: DragEvent| {
        event.prevent_default();
        is_dragging.set(false);

        if let Some(data_transfer) = event.data_transfer() {
            if let Some(files) = data_transfer.files() {
                if let Some(file) = files.get(0) {
                    spawn_local(handle_file_async(file, state));
                }
            }
        }
    };
    let on_file_change = move |event: Event| {
        let target = event.target().expect("file input event target");
        let input: HtmlInputElement = target.unchecked_into();
        if let Some(files) = input.files() {
            if let Some(file) = files.get(0) {
                input.set_value("");
                spawn_local(handle_file_async(file, state));
            }
        }
    };
    let open_file_dialog = move |_| {
        let input_ref = file_input_ref;
        request_animation_frame(move || {
            if let Some(input) = input_ref.get_untracked() {
                input.click();
            }
        });
    };

    view! {
        <section class="file-picker" aria-label="Open a vault">
            <div class="picker-column">
                <Show when=server::storage_enabled>
                    <section class="vault-library" aria-labelledby="vault-library-title">
                        <h2 id="vault-library-title" class="vault-library-title">"Vaults"</h2>
                        <Show
                            when=move || storage_loaded.get()
                            fallback=|| view! { <p class="vault-status">"Loading…"</p> }
                        >
                            <Show
                                when=move || !stored_files.get().is_empty()
                                fallback=|| view! { <p class="vault-status">"No stored vaults."</p> }
                            >
                                <div class="vault-list">
                                    {move || stored_files.get().into_iter().map(|file| {
                                        let id = file.id.clone();
                                        let name = file.name.clone();
                                        let display_name = file.name.clone();
                                        view! {
                                            <button
                                                class="vault-row"
                                                type="button"
                                                on:click=move |_| {
                                                    let id = id.clone();
                                                    let name = name.clone();
                                                    spawn_local(open_stored_file(id, name, state));
                                                }
                                            >
                                                <span class="vault-row-icon" aria-hidden="true">
                                                    <svg viewBox="0 0 24 24" width="18" height="18">
                                                        <path fill="currentColor" d="M17 8h-1V6a4 4 0 0 0-8 0v2H7a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2Zm-7-2a2 2 0 0 1 4 0v2h-4V6Zm3 10.73V18h-2v-1.27a2 2 0 1 1 2 0Z"/>
                                                    </svg>
                                                </span>
                                                <span class="vault-row-copy">
                                                    <strong>{display_name}</strong>
                                                    <span>{format_size(file.size)}</span>
                                                </span>
                                                <svg class="vault-row-arrow" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
                                                    <path fill="currentColor" d="m9.3 17.3 4.6-4.6a1 1 0 0 0 0-1.4L9.3 6.7l1.4-1.4 4.6 4.6a3 3 0 0 1 0 4.2l-4.6 4.6-1.4-1.4Z"/>
                                                </svg>
                                            </button>
                                        }
                                    }).collect_view()}
                                </div>
                            </Show>
                        </Show>
                    </section>
                </Show>

                <div
                    class="drop-zone"
                    class:dragging=move || is_dragging.get()
                    on:dragover=on_drag_over
                    on:dragleave=on_drag_leave
                    on:drop=on_drop
                >
                    <p class="drop-hint">"Drop a .kdbx file here or"</p>
                    <button class="btn btn-primary" type="button" on:click=open_file_dialog>
                        {if server::storage_enabled() { "Upload database" } else { "Choose database" }}
                    </button>
                    <input
                        type="file"
                        accept=".kdbx"
                        class="visually-hidden"
                        node_ref=file_input_ref
                        on:change=on_file_change
                    />
                </div>

                <Show when=move || state.helper_status.get() == HelperStatus::Unavailable>
                    <div class="helper-notice">
                        <span>"For faster unlock, run the local helper:"</span>
                        <code class="run-command">"nix run github:johnrichardrinehart/keeweb-rs#helper"</code>
                    </div>
                </Show>

                <Show when=move || state.error_message.get().is_some()>
                    <p class="file-error" role="alert">
                        {move || state.error_message.get().unwrap_or_default()}
                    </p>
                </Show>
            </div>
        </section>
    }
}

async fn handle_file_async(file: File, state: AppState) {
    let name = file.name();
    state.error_message.set(None);

    if !name.to_lowercase().ends_with(".kdbx") {
        state
            .error_message
            .set(Some("Please select a .kdbx file".to_string()));
        return;
    }
    let source = if server::storage_enabled() {
        // Once stored, an upload is a server vault like any other: saves replace it.
        match server::create(&file, &name).await {
            Ok(written) => DatabaseSource::Server {
                id: written.id,
                name: written.name,
                revision: written.revision,
            },
            Err(error) => {
                state.error_message.set(Some(error));
                return;
            }
        }
    } else {
        DatabaseSource::Local { name }
    };

    match files::read_file(&file).await {
        Ok(data) => state.set_pending_file(data, source),
        Err(error) => state.error_message.set(Some(error)),
    }
}

async fn open_stored_file(id: String, name: String, state: AppState) {
    // Server vaults are identified by their id, see `DatabaseSource::vault_key`.
    if state.switch_to_vault(&id) {
        return;
    }
    state.error_message.set(None);
    match server::download(&id, &name).await {
        Ok((data, revision)) => {
            state.set_pending_file(data, DatabaseSource::Server { id, name, revision })
        }
        Err(error) => state.error_message.set(Some(error)),
    }
}

fn request_animation_frame(f: impl FnOnce() + 'static) {
    let closure = Closure::once_into_js(f);
    web_sys::window()
        .expect("window")
        .request_animation_frame(closure.as_ref().unchecked_ref())
        .expect("request animation frame");
}
