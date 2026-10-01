//! File picker component with drag-and-drop support

use leptos::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{DragEvent, Event, File, HtmlInputElement, Request, RequestInit, Response};

use crate::state::{AppState, DatabaseSource, HelperStatus};

#[derive(Clone, Deserialize)]
struct StoredFile {
    id: String,
    name: String,
    size: u64,
}

/// File picker component
#[component]
pub fn FilePicker() -> impl IntoView {
    let state = expect_context::<AppState>();
    let is_dragging = create_rw_signal(false);
    let file_input_ref = create_node_ref::<leptos::html::Input>();
    let stored_files = create_rw_signal(Vec::<StoredFile>::new());
    let storage_loaded = create_rw_signal(!server_storage_enabled());

    if server_storage_enabled() {
        spawn_local(async move {
            match list_stored_files().await {
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
        <section class="file-picker" aria-labelledby="welcome-title">
            <div class="welcome-shell">
                <div class="welcome-copy">
                    <span class="eyebrow">"Local-first password manager"</span>
                    <h2 id="welcome-title">"Your vault, opened where it belongs."</h2>
                    <p class="welcome-lede">
                        "Open a vault from your private server or add another one. Database files stay encrypted until this browser unlocks them."
                    </p>

                    <div class="trust-list" aria-label="Privacy guarantees">
                        <div class="trust-item">
                            <span class="trust-icon" aria-hidden="true">"01"</span>
                            <div>
                                <strong>"One private vault library"</strong>
                                <span>"Choose any stored KDBX database from this page."</span>
                            </div>
                        </div>
                        <div class="trust-item">
                            <span class="trust-icon" aria-hidden="true">"02"</span>
                            <div>
                                <strong>"Decryption stays local"</strong>
                                <span>"The server sends encrypted bytes. Your password stays here."</span>
                            </div>
                        </div>
                        <div class="trust-item">
                            <span class="trust-icon" aria-hidden="true">"03"</span>
                            <div>
                                <strong>"Native unlock, on your machine"</strong>
                                <span>"The optional helper accelerates Argon2 on localhost."</span>
                            </div>
                        </div>
                    </div>

                    <div
                        class="helper-card"
                        class:helper-card-connected=move || state.helper_status.get() == HelperStatus::Connected
                        aria-live="polite"
                    >
                        <div class="helper-card-heading">
                            <span class="status-dot"></span>
                            <strong>
                                {move || match state.helper_status.get() {
                                    HelperStatus::Checking => "Looking for the local helper",
                                    HelperStatus::Connected => "Native unlock is ready",
                                    HelperStatus::Unavailable => "Native helper is not running",
                                }}
                            </strong>
                        </div>
                        {move || match state.helper_status.get() {
                            HelperStatus::Checking => view! {
                                <p>"Checking 127.0.0.1:8081…"</p>
                            }.into_view(),
                            HelperStatus::Connected => view! {
                                <p>"KeeWeb will use native Argon2 for a faster unlock."</p>
                            }.into_view(),
                            HelperStatus::Unavailable => view! {
                                <div>
                                    <p>"Start it in another terminal. Browser unlock remains available."</p>
                                    <code class="run-command">"nix run github:johnrichardrinehart/keeweb-rs#helper"</code>
                                </div>
                            }.into_view(),
                        }}
                    </div>
                </div>

                <div class="vault-workspace">
                    <Show when=server_storage_enabled>
                        <section class="vault-library" aria-labelledby="vault-library-title">
                            <div class="vault-library-header">
                                <div>
                                    <span class="drop-kicker">"Private server"</span>
                                    <h3 id="vault-library-title">"Your vaults"</h3>
                                </div>
                                <span class="vault-count">
                                    {move || stored_files.get().len()}
                                </span>
                            </div>
                            <Show
                                when=move || storage_loaded.get()
                                fallback=|| view! {
                                    <div class="vault-loading">"Loading encrypted vaults…"</div>
                                }
                            >
                                <Show
                                    when=move || !stored_files.get().is_empty()
                                    fallback=|| view! {
                                        <div class="vault-empty">
                                            <strong>"No stored vaults yet"</strong>
                                            <span>"Add your first database below."</span>
                                        </div>
                                    }
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
                        class:drop-zone-compact=server_storage_enabled()
                        class:dragging=move || is_dragging.get()
                        on:dragover=on_drag_over
                        on:dragleave=on_drag_leave
                        on:drop=on_drop
                    >
                        <div class="drop-zone-content">
                            <div class="drop-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" width="56" height="56">
                                    <path fill="currentColor" d="M12 2 4.5 5v5.8c0 4.7 3.2 9.1 7.5 10.2 4.3-1.1 7.5-5.5 7.5-10.2V5L12 2Zm0 5a2.5 2.5 0 0 1 1 4.8V16h-2v-4.2A2.5 2.5 0 0 1 12 7Z"/>
                                </svg>
                            </div>
                            <span class="drop-kicker">
                                {if server_storage_enabled() { "Add a vault" } else { "KeePass database" }}
                            </span>
                            <h3>"Open a .kdbx file"</h3>
                            <p>
                                {if server_storage_enabled() {
                                    "Upload an encrypted database or drag it here."
                                } else {
                                    "Choose a file or drag it into this window."
                                }}
                            </p>
                            <button class="btn btn-primary btn-large" type="button" on:click=open_file_dialog>
                                {if server_storage_enabled() { "Upload database" } else { "Choose database" }}
                            </button>
                            <input
                                type="file"
                                accept=".kdbx"
                                class="visually-hidden"
                                node_ref=file_input_ref
                                on:change=on_file_change
                            />
                            <span class="drop-footnote">"KeePass 2 · KDBX 4"</span>
                        </div>
                    </div>
                </div>
            </div>

            <Show when=move || state.error_message.get().is_some()>
                <p class="file-error" role="alert">
                    {move || state.error_message.get().unwrap_or_default()}
                </p>
            </Show>
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
    if server_storage_enabled() {
        if let Err(error) = upload_file(&file, &name).await {
            state.error_message.set(Some(error));
            return;
        }
    }

    match JsFuture::from(file.array_buffer()).await {
        Ok(array_buffer) => {
            let data = js_sys::Uint8Array::new(&array_buffer).to_vec();
            state.set_pending_file(data, DatabaseSource::Local { name });
        }
        Err(error) => {
            log::error!("Failed to read file: {:?}", error);
            state
                .error_message
                .set(Some("Failed to read file".to_string()));
        }
    }
}

async fn upload_file(file: &File, name: &str) -> Result<(), String> {
    let encoded_name = js_sys::encode_uri_component(name);
    let url = format!("/api/files/{encoded_name}");
    let options = RequestInit::new();
    options.set_method("PUT");
    options.set_body(file.as_ref());
    let request = Request::new_with_str_and_init(&url, &options)
        .map_err(|_| "Failed to create the upload request".to_string())?;
    let response = fetch_request(&request).await?;

    match response.status() {
        201 => Ok(()),
        409 => Err(format!("A database named {name} already exists.")),
        status => Err(format!(
            "The server rejected the upload with HTTP {status}."
        )),
    }
}

async fn list_stored_files() -> Result<Vec<StoredFile>, String> {
    let response = fetch_url("/api/files").await?;
    if !response.ok() {
        return Err(format!(
            "Failed to list stored databases: HTTP {}.",
            response.status()
        ));
    }
    let value = JsFuture::from(
        response
            .json()
            .map_err(|_| "Failed to read the database list".to_string())?,
    )
    .await
    .map_err(|_| "Failed to read the database list".to_string())?;
    serde_wasm_bindgen::from_value(value)
        .map_err(|_| "The server returned an invalid database list".to_string())
}

async fn open_stored_file(id: String, name: String, state: AppState) {
    state.error_message.set(None);
    let encoded_id = js_sys::encode_uri_component(&id);
    let response = match fetch_url(&format!("/api/files/{encoded_id}")).await {
        Ok(response) if response.ok() => response,
        Ok(response) => {
            state.error_message.set(Some(format!(
                "Failed to download {name}: HTTP {}.",
                response.status()
            )));
            return;
        }
        Err(error) => {
            state.error_message.set(Some(error));
            return;
        }
    };
    let array_buffer = match response.array_buffer() {
        Ok(promise) => match JsFuture::from(promise).await {
            Ok(value) => value,
            Err(_) => {
                state
                    .error_message
                    .set(Some(format!("Failed to download {name}.")));
                return;
            }
        },
        Err(_) => {
            state
                .error_message
                .set(Some(format!("Failed to download {name}.")));
            return;
        }
    };
    let data = js_sys::Uint8Array::new(&array_buffer).to_vec();
    state.set_pending_file(data, DatabaseSource::Backend { path: id, name });
}

async fn fetch_url(url: &str) -> Result<Response, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let value = JsFuture::from(window.fetch_with_str(url))
        .await
        .map_err(|_| "The KeePass server is unavailable".to_string())?;
    value
        .dyn_into()
        .map_err(|_| "The server returned an invalid response".to_string())
}

async fn fetch_request(request: &Request) -> Result<Response, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let value = JsFuture::from(window.fetch_with_request(request))
        .await
        .map_err(|_| "The KeePass server is unavailable".to_string())?;
    value
        .dyn_into()
        .map_err(|_| "The server returned an invalid response".to_string())
}

fn server_storage_enabled() -> bool {
    option_env!("KEEWEB_SERVER_STORAGE") == Some("1")
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn request_animation_frame(f: impl FnOnce() + 'static) {
    let closure = Closure::once_into_js(f);
    web_sys::window()
        .expect("window")
        .request_animation_frame(closure.as_ref().unchecked_ref())
        .expect("request animation frame");
}
