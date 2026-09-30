//! File picker component with drag-and-drop support

use leptos::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{DragEvent, Event, File, HtmlInputElement, Request, RequestInit, Response};

use crate::state::{AppState, DatabaseSource};

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
    let stored_files = create_rw_signal(Vec::<StoredFile>::new());
    let file_input_ref = create_node_ref::<leptos::html::Input>();

    if server_storage_enabled() {
        spawn_local(async move {
            match list_stored_files().await {
                Ok(files) => stored_files.set(files),
                Err(error) => state.error_message.set(Some(error)),
            }
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
        <div class="file-picker">
            <div
                class="drop-zone"
                class:dragging=move || is_dragging.get()
                on:dragover=on_drag_over
                on:dragleave=on_drag_leave
                on:drop=on_drop
            >
                <div class="drop-zone-content">
                    <div class="drop-icon">
                        <svg viewBox="0 0 24 24" width="64" height="64">
                            <path fill="currentColor" d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/>
                        </svg>
                    </div>
                    <h2>"Drop your KDBX file here"</h2>
                    <p>"or"</p>
                    <button class="btn btn-primary" on:click=open_file_dialog>
                        "Browse Files"
                    </button>
                    <input
                        type="file"
                        accept=".kdbx"
                        style="display: none"
                        node_ref=file_input_ref
                        on:change=on_file_change
                    />
                </div>
            </div>

            <Show when=move || state.error_message.get().is_some()>
                <p class="file-error" role="alert">
                    {move || state.error_message.get().unwrap_or_default()}
                </p>
            </Show>

            <Show when=server_storage_enabled>
                <section class="stored-files">
                    <h3>"Stored databases"</h3>
                    <Show
                        when=move || !stored_files.get().is_empty()
                        fallback=|| view! { <p>"No databases are stored."</p> }
                    >
                        <div class="stored-file-list">
                            {move || stored_files.get().into_iter().map(|file| {
                                let id = file.id.clone();
                                let name = file.name.clone();
                                let display_name = file.name.clone();
                                view! {
                                    <button
                                        class="stored-file"
                                        type="button"
                                        on:click=move |_| {
                                            let id = id.clone();
                                            let name = name.clone();
                                            spawn_local(open_stored_file(id, name, state));
                                        }
                                    >
                                        <span>{display_name}</span>
                                        <span class="stored-file-size">{format_size(file.size)}</span>
                                    </button>
                                }
                            }).collect_view()}
                        </div>
                    </Show>
                </section>
            </Show>

            <div class="file-picker-options">
                <h3>"Or connect to cloud storage"</h3>
                <div class="cloud-buttons">
                    <button class="btn btn-cloud" disabled=true title="Coming soon">
                        <span class="cloud-icon google-drive"></span>
                        "Google Drive"
                    </button>
                    <button class="btn btn-cloud" disabled=true title="Coming soon">
                        <span class="cloud-icon dropbox"></span>
                        "Dropbox"
                    </button>
                    <button class="btn btn-cloud" disabled=true title="Coming soon">
                        <span class="cloud-icon box"></span>
                        "Box"
                    </button>
                </div>
            </div>

            <div class="file-picker-footer">
                <p class="security-note">
                    {if server_storage_enabled() {
                        "Dropped files stay encrypted and are copied to this private server."
                    } else {
                        "Your files are processed entirely in your browser. No data is sent to any server."
                    }}
                </p>
            </div>
        </div>
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
