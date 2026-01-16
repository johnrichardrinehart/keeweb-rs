//! File picker component with drag-and-drop support

use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{DragEvent, Event, File, HtmlInputElement};

use crate::state::{AppState, DatabaseSource};

/// File picker component
#[component]
pub fn FilePicker() -> impl IntoView {
    let state = expect_context::<AppState>();

    let is_dragging = create_rw_signal(false);
    let file_input_ref = create_node_ref::<leptos::html::Input>();

    // Handle drag over
    let on_drag_over = move |ev: DragEvent| {
        ev.prevent_default();
        is_dragging.set(true);
    };

    // Handle drag leave
    let on_drag_leave = move |ev: DragEvent| {
        ev.prevent_default();
        is_dragging.set(false);
    };

    // Handle drop
    let on_drop = move |ev: DragEvent| {
        ev.prevent_default();
        is_dragging.set(false);

        if let Some(data_transfer) = ev.data_transfer() {
            if let Some(files) = data_transfer.files() {
                if let Some(file) = files.get(0) {
                    spawn_local(handle_file_async(file, state));
                }
            }
        }
    };

    // Handle file input change
    let on_file_change = move |ev: Event| {
        let target = ev.target().unwrap();
        let input: HtmlInputElement = target.unchecked_into();
        if let Some(files) = input.files() {
            if let Some(file) = files.get(0) {
                // Reset input value so same file can be selected again
                input.set_value("");
                spawn_local(handle_file_async(file, state));
            }
        }
    };

    // Open file dialog - use request_animation_frame to avoid closure recursion
    let open_file_dialog = move |_| {
        let input_ref = file_input_ref;
        // Defer the click to next frame to avoid closure recursion
        request_animation_frame(move || {
            if let Some(input) = input_ref.get() {
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
                    "Your files are processed entirely in your browser. "
                    "No data is sent to any server."
                </p>
            </div>
        </div>
    }
}

/// Handle a selected file asynchronously
async fn handle_file_async(file: File, state: AppState) {
    let name = file.name();

    // Validate file extension
    if !name.to_lowercase().ends_with(".kdbx") {
        state
            .error_message
            .set(Some("Please select a .kdbx file".to_string()));
        return;
    }

    log::debug!("Reading file: {}", name);

    let source = DatabaseSource::Local { name };

    // Read file using the File API's arrayBuffer() method (returns a Promise)
    match JsFuture::from(file.array_buffer()).await {
        Ok(array_buffer) => {
            let data = js_sys::Uint8Array::new(&array_buffer).to_vec();
            log::debug!("File read successfully, {} bytes", data.len());
            state.set_pending_file(data, source);
        }
        Err(e) => {
            log::error!("Failed to read file: {:?}", e);
            state
                .error_message
                .set(Some("Failed to read file".to_string()));
        }
    }
}

/// Request animation frame helper to defer execution
fn request_animation_frame(f: impl FnOnce() + 'static) {
    let closure = Closure::once_into_js(f);
    web_sys::window()
        .unwrap()
        .request_animation_frame(closure.as_ref().unchecked_ref())
        .unwrap();
}
