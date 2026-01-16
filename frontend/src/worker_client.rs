//! Web Worker client for offloading expensive operations

use js_sys::{Array, Object, Reflect, Uint8Array};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Blob, BlobPropertyBag, MessageEvent, Url, Worker};

/// Result of a database unlock operation
#[derive(Debug, Clone)]
pub struct UnlockResult {
    pub entries_json: String,
    pub groups_json: String,
    pub metadata_json: String,
}

/// Callback type for unlock completion
type UnlockCallback = Box<dyn FnOnce(Result<UnlockResult, String>)>;

/// Client for communicating with the unlock worker
pub struct WorkerClient {
    worker: Worker,
    pending_requests: Rc<RefCell<HashMap<u32, UnlockCallback>>>,
    next_id: Rc<RefCell<u32>>,
}

/// Generate worker script that can load WASM dynamically
fn create_worker_script() -> String {
    // The worker script as a string - loads the standalone keeweb-wasm module (no Leptos/DOM dependencies)
    r#"
// Web Worker for KeeWeb-RS database operations
let wasmModule = null;
let WasmDatabase = null;

// Initialize the WASM module
async function initWasm() {
    if (wasmModule) return;

    try {
        const baseUrl = self.location.origin;

        // Load the standalone keeweb-wasm module (built separately with wasm-pack)
        // This module has no DOM dependencies and can run in a worker
        const jsUrl = baseUrl + '/wasm/keeweb_wasm.js';
        const wasmUrl = baseUrl + '/wasm/keeweb_wasm_bg.wasm';

        console.log('[Worker] Loading keeweb-wasm from:', jsUrl);

        // Dynamic import for ES modules in worker
        const module = await import(jsUrl);

        // Initialize WASM with the wasm file path
        wasmModule = await module.default(wasmUrl);

        WasmDatabase = module.WasmDatabase;
        console.log('[Worker] WASM module initialized successfully');
    } catch (e) {
        console.error('[Worker] Failed to initialize WASM:', e);
        throw e;
    }
}

// Handle messages from main thread
self.onmessage = async function(event) {
    const { type, id, payload } = event.data;
    console.log('[Worker] Received message:', type, 'id:', id);

    try {
        await initWasm();

        switch (type) {
            case 'unlock':
                await handleUnlock(id, payload);
                break;
            default:
                self.postMessage({
                    id,
                    type: 'error',
                    error: 'Unknown message type: ' + type
                });
        }
    } catch (e) {
        console.error('[Worker] Error handling message:', e);
        self.postMessage({
            id,
            type: 'error',
            error: e.toString()
        });
    }
};

// Handle database unlock request
async function handleUnlock(id, { data, password }) {
    console.log('[Worker] Starting unlock, data size:', data.length);

    try {
        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);

        console.log('[Worker] Opening database (Argon2 key derivation in progress)...');
        const startTime = performance.now();

        const db = new WasmDatabase(dataArray, password);

        const elapsed = performance.now() - startTime;
        console.log('[Worker] Database opened in', elapsed.toFixed(0), 'ms');

        const entriesJson = db.getEntries();
        const groupsJson = db.getGroups();
        const metadataJson = db.getMetadata();

        self.postMessage({
            id,
            type: 'unlock_success',
            result: {
                entriesJson,
                groupsJson,
                metadataJson,
            }
        });

        self.currentDatabase = db;
    } catch (e) {
        console.error('[Worker] Unlock failed:', e);
        self.postMessage({
            id,
            type: 'unlock_error',
            error: e.toString()
        });
    }
}

console.log('[Worker] Worker script loaded');
"#.to_string()
}

impl WorkerClient {
    /// Create a new worker client
    pub fn new() -> Result<Self, JsValue> {
        log::debug!("Creating worker client");

        // Create worker from inline script using Blob URL
        let script = create_worker_script();
        let blob_parts = Array::new();
        blob_parts.push(&JsValue::from_str(&script));

        let mut options = BlobPropertyBag::new();
        options.set_type("application/javascript");

        let blob = Blob::new_with_str_sequence_and_options(&blob_parts, &options)?;
        let url = Url::create_object_url_with_blob(&blob)?;

        log::debug!("Created worker blob URL: {}", url);

        let mut worker_options = web_sys::WorkerOptions::new();
        worker_options.set_type(web_sys::WorkerType::Module);

        let worker = Worker::new_with_options(&url, &worker_options)?;

        let pending_requests: Rc<RefCell<HashMap<u32, UnlockCallback>>> =
            Rc::new(RefCell::new(HashMap::new()));
        let pending_clone = pending_requests.clone();

        // Set up message handler
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();

            // Extract message fields
            let id = Reflect::get(&data, &"id".into())
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u32);

            let msg_type = Reflect::get(&data, &"type".into())
                .ok()
                .and_then(|v| v.as_string());

            log::debug!("Worker message received: type={:?}, id={:?}", msg_type, id);

            if let (Some(id), Some(msg_type)) = (id, msg_type) {
                // Get the callback for this request
                let callback = pending_clone.borrow_mut().remove(&id);

                if let Some(callback) = callback {
                    match msg_type.as_str() {
                        "unlock_success" => {
                            let result = Reflect::get(&data, &"result".into()).ok();
                            if let Some(result) = result {
                                let entries_json = Reflect::get(&result, &"entriesJson".into())
                                    .ok()
                                    .and_then(|v| v.as_string())
                                    .unwrap_or_default();
                                let groups_json = Reflect::get(&result, &"groupsJson".into())
                                    .ok()
                                    .and_then(|v| v.as_string())
                                    .unwrap_or_default();
                                let metadata_json = Reflect::get(&result, &"metadataJson".into())
                                    .ok()
                                    .and_then(|v| v.as_string())
                                    .unwrap_or_default();

                                callback(Ok(UnlockResult {
                                    entries_json,
                                    groups_json,
                                    metadata_json,
                                }));
                            } else {
                                callback(Err("Missing result in response".to_string()));
                            }
                        }
                        "unlock_error" | "error" => {
                            let error = Reflect::get(&data, &"error".into())
                                .ok()
                                .and_then(|v| v.as_string())
                                .unwrap_or_else(|| "Unknown error".to_string());
                            callback(Err(error));
                        }
                        _ => {
                            callback(Err(format!("Unknown message type: {}", msg_type)));
                        }
                    }
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);

        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // Set up error handler
        let onerror = Closure::wrap(Box::new(move |event: web_sys::ErrorEvent| {
            log::error!("Worker error: {:?}", event.message());
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);

        worker.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        log::debug!("Worker client created successfully");

        Ok(Self {
            worker,
            pending_requests,
            next_id: Rc::new(RefCell::new(0)),
        })
    }

    /// Request database unlock in the worker
    pub fn unlock<F>(&self, data: Vec<u8>, password: String, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        let id = {
            let mut next = self.next_id.borrow_mut();
            let id = *next;
            *next += 1;
            id
        };

        log::debug!("Sending unlock request, id={}, data_len={}", id, data.len());

        // Store the callback
        self.pending_requests
            .borrow_mut()
            .insert(id, Box::new(callback));

        // Create the message object
        let message = Object::new();
        Reflect::set(&message, &"type".into(), &"unlock".into()).unwrap();
        Reflect::set(&message, &"id".into(), &JsValue::from_f64(id as f64)).unwrap();

        // Create payload with data and password
        let payload = Object::new();

        // Convert Vec<u8> to Uint8Array for transfer
        let data_array = Uint8Array::from(data.as_slice());
        Reflect::set(&payload, &"data".into(), &data_array).unwrap();
        Reflect::set(&payload, &"password".into(), &password.into()).unwrap();

        Reflect::set(&message, &"payload".into(), &payload).unwrap();

        // Create transfer array for the data buffer
        let transfer = Array::new();
        transfer.push(&data_array.buffer());

        // Post message with transfer
        if let Err(e) = self.worker.post_message_with_transfer(&message, &transfer) {
            log::error!("Failed to post message to worker: {:?}", e);
            // Call the callback with error
            if let Some(callback) = self.pending_requests.borrow_mut().remove(&id) {
                callback(Err(format!("Failed to send to worker: {:?}", e)));
            }
        }
    }
}

impl Default for WorkerClient {
    fn default() -> Self {
        Self::new().expect("Failed to create worker client")
    }
}
