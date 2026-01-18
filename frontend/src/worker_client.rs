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
    #[allow(dead_code)]
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
fn create_worker_script(base_url: &str) -> String {
    // The worker script as a string - loads keeweb-wasm and uses @very-amused/argon2-wasm for pthread support
    // Uses dynamic import() for ES modules since we're a module worker
    // Base URL is injected to handle subpath deployments (e.g., GitHub Pages)
    let mut script = String::from(r#"
// Web Worker for KeeWeb-RS database operations
// Uses @very-amused/argon2-wasm with pthread support for fast parallel key derivation

// Base URL injected from main thread (handles subpath deployments like GitHub Pages)
const BASE_URL = ""#);
    script.push_str(base_url);
    script.push_str(r#"";

let wasmModule = null;
let argon2Worker = null;
let argon2Ready = false;
let getKdfParams = null;
let decryptWithDerivedKey = null;
let unlockDatabase = null;
let WasmDatabase = null;

// Queue for argon2 worker responses (argon2 library doesn't echo back IDs)
let argon2PendingQueue = [];

// Argon2 Methods enum (from @very-amused/argon2-wasm)
const Argon2Methods = {
    LoadArgon2: 0,
    Hash2i: 1,
    Hash2d: 2,
    Hash2id: 3,
    Unload: 4
};

// Initialize argon2 worker with configurable pthread support
// usePthread: true for multi-threaded (may deadlock with 1GB+ memory), false for SIMD-only
async function initArgon2Worker(baseUrl, usePthread = true) {
    return new Promise((resolve, reject) => {
        const workerUrl = baseUrl + '/argon2-pthread/build/worker.js';
        argon2Worker = new Worker(workerUrl);

        // argon2 library doesn't echo back IDs, so we use a queue
        argon2Worker.onmessage = (event) => {
            const { code, body, message } = event.data;
            const pending = argon2PendingQueue.shift();
            if (pending) {
                if (code === 0) {
                    pending.resolve(body);
                } else {
                    pending.reject(new Error(message || 'Argon2 error code: ' + code));
                }
            }
        };

        argon2Worker.onerror = (e) => {
            const pending = argon2PendingQueue.shift();
            if (pending) {
                pending.reject(e);
            }
            reject(e);
        };

        // Queue the load request
        argon2PendingQueue.push({ resolve, reject });

        // Load argon2 WASM - SIMD always enabled, pthread configurable
        argon2Worker.postMessage({
            method: Argon2Methods.LoadArgon2,
            params: {
                wasmRoot: baseUrl + '/argon2-pthread/build',
                simd: true,
                pthread: usePthread
            }
        });
    });
}

// Run argon2 hash via the pthread worker
async function runArgon2(type, password, salt, timeCost, memoryCost, threads, hashLen) {
    return new Promise((resolve, reject) => {
        // Queue the hash request
        argon2PendingQueue.push({ resolve, reject });

        // Select method based on type (0=2d, 2=2id)
        const method = type === 0 ? Argon2Methods.Hash2d : Argon2Methods.Hash2id;

        argon2Worker.postMessage({
            method,
            params: {
                password,
                salt,
                timeCost,
                memoryCost,
                threads,
                hashLen
            }
        });
    });
}

// Initialize keeweb-wasm only (for decrypt_with_key)
async function initKeewebWasm() {
    if (wasmModule) return;

    try {
        const jsUrl = BASE_URL + '/wasm/keeweb_wasm.js';
        const wasmUrl = BASE_URL + '/wasm/keeweb_wasm_bg.wasm';

        const module = await import(jsUrl);
        wasmModule = await module.default({ module_or_path: wasmUrl });

        getKdfParams = module.getKdfParams;
        decryptWithDerivedKey = module.decryptWithDerivedKey;
        unlockDatabase = module.unlockDatabase;
        WasmDatabase = module.WasmDatabase;
    } catch (e) {
        throw e;
    }
}

// Track which argon2 mode is loaded
let argon2Mode = null; // 'pthread' or 'simd'

// Initialize WASM modules including argon2 (for unlock_fast)
// usePthread: true for multi-threaded, false for SIMD-only (for high-memory databases)
async function initWasm(usePthread = true) {
    const targetMode = usePthread ? 'pthread' : 'simd';

    // If argon2 is already loaded in the wrong mode, we need to recreate the worker
    if (argon2Ready && argon2Mode !== targetMode) {
        if (argon2Worker) {
            argon2Worker.terminate();
            argon2Worker = null;
        }
        argon2Ready = false;
        argon2Mode = null;
    }

    if (wasmModule && argon2Ready && argon2Mode === targetMode) return;

    try {
        // Load keeweb-wasm first
        await initKeewebWasm();

        // Load argon2 worker with appropriate mode
        if (!argon2Ready) {
            await initArgon2Worker(BASE_URL, usePthread);
            argon2Ready = true;
            argon2Mode = targetMode;
        }
    } catch (e) {
        throw e;
    }
}

// Handle messages from main thread
self.onmessage = async function(event) {
    const { type, id, payload } = event.data;

    try {
        switch (type) {
            case 'unlock':
                // Standard unlock - needs keeweb-wasm only (uses rust-argon2, single-threaded)
                await initKeewebWasm();
                await handleUnlock(id, payload);
                break;
            case 'unlock_fast':
                // Fast unlock with pthread - needs both keeweb-wasm and argon2 (SIMD+pthread)
                await initWasm(true);
                await handleUnlockFast(id, payload, 'pthread');
                break;
            case 'unlock_fast_simd':
                // Fast unlock SIMD-only - for high-memory databases where pthread deadlocks
                await initWasm(false);
                await handleUnlockFast(id, payload, 'simd');
                break;
            case 'decrypt_with_key':
                // Decrypt with pre-computed key - only needs keeweb-wasm
                await initKeewebWasm();
                await handleDecryptWithKey(id, payload);
                break;
            default:
                self.postMessage({
                    id,
                    type: 'error',
                    error: 'Unknown message type: ' + type
                });
        }
    } catch (e) {
        self.postMessage({
            id,
            type: 'error',
            error: e ? (e.message || e.toString()) : 'Unknown error'
        });
    }
};

// Fast unlock using argon2 with SIMD (and optionally multi-threading)
// mode: 'pthread' for multi-threaded, 'simd' for SIMD-only
async function handleUnlockFast(id, { data, password }, mode = 'pthread') {
    try {
        // Verify argon2 worker is ready
        if (!argon2Ready) {
            throw new Error('Argon2 worker not ready');
        }

        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);

        // Step 1: Extract KDF parameters from KDBX header
        const kdfParams = getKdfParams(dataArray, password);

        // Step 2: Run Argon2 with SIMD (and pthreads if enabled)
        // argon2 type values: 0=Argon2d, 2=Argon2id
        const argon2Type = kdfParams.kdfType === 'argon2d' ? 0 : 2;

        // Get composite key and salt
        const compositeKey = new Uint8Array(kdfParams.compositeKey);
        const salt = new Uint8Array(kdfParams.salt);

        // Run argon2 via the pthread worker
        const hash = await runArgon2(
            argon2Type,
            compositeKey,           // password (composite key)
            salt,                   // salt
            Number(kdfParams.iterations),   // timeCost
            Number(kdfParams.memoryKb),     // memoryCost in KB
            kdfParams.parallelism,          // threads
            32                              // hashLen
        );

        const argon2Result = { hash: new Uint8Array(hash) };

        // Step 3: Decrypt database with derived key
        const decryptResult = decryptWithDerivedKey(dataArray, password, argon2Result.hash);

        self.postMessage({
            id,
            type: 'unlock_success',
            result: {
                entriesJson: decryptResult.entriesJson,
                groupsJson: decryptResult.groupsJson,
                metadataJson: decryptResult.metadataJson,
            }
        });
    } catch (e) {
        // Fall back to standard unlock
        await handleUnlock(id, { data, password });
    }
}

// Standard unlock (uses unlockDatabase which runs rust-argon2 internally)
// This uses the same XML parsing path as handleUnlockFast, ensuring protected attributes work
async function handleUnlock(id, { data, password }) {
    try {
        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);

        // Use unlockDatabase which:
        // 1. Runs Argon2 internally (slower than JS SIMD, but unified code path)
        // 2. Decrypts the payload
        // 3. Preserves ProtectInMemory attributes in XML parsing
        const result = unlockDatabase(dataArray, password);

        self.postMessage({
            id,
            type: 'unlock_success',
            result: {
                entriesJson: result.entriesJson,
                groupsJson: result.groupsJson,
                metadataJson: result.metadataJson,
            }
        });
    } catch (e) {
        self.postMessage({
            id,
            type: 'unlock_error',
            error: e ? (e.message || e.toString()) : 'Unknown error'
        });
    }
}

// Decrypt with pre-computed key (from main thread parallel argon2)
async function handleDecryptWithKey(id, { data, password, derivedKey }) {
    try {
        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);
        const keyArray = derivedKey instanceof Uint8Array ? derivedKey : new Uint8Array(derivedKey);

        // Use the decryptWithDerivedKey function from keeweb-wasm
        const decryptResult = decryptWithDerivedKey(dataArray, password, keyArray);

        self.postMessage({
            id,
            type: 'unlock_success',
            result: {
                entriesJson: decryptResult.entriesJson,
                groupsJson: decryptResult.groupsJson,
                metadataJson: decryptResult.metadataJson,
            }
        });
    } catch (e) {
        self.postMessage({
            id,
            type: 'unlock_error',
            error: e ? (e.message || e.toString()) : 'Unknown error'
        });
    }
}
"#);
    script
}

/// Get the base URL for assets, handling subpath deployments (e.g., GitHub Pages)
fn get_base_url() -> String {
    let window = web_sys::window().expect("no window");
    let location = window.location();
    let origin = location.origin().unwrap_or_default();
    let pathname = location.pathname().unwrap_or_default();

    // For subpath deployments, we need to include the path up to the app root
    // e.g., for https://user.github.io/repo-name/, we need /repo-name
    // The pathname typically looks like /repo-name/ or /repo-name/index.html
    // We want to extract just /repo-name (without trailing content after the last /)

    // Find the base path - everything up to but not including the last segment
    // unless it's just "/" in which case we use that
    let base_path = if pathname == "/" {
        String::new()
    } else {
        // Remove trailing slash if present, then find the last slash
        let trimmed = pathname.trim_end_matches('/');
        // For paths like /keeweb-rs or /keeweb-rs/some/page
        // we want to keep everything - the app is served from the subpath root
        // Check if there's an index.html or other file at the end
        if trimmed.ends_with(".html") || trimmed.ends_with(".js") {
            // Remove the filename to get the directory
            if let Some(pos) = trimmed.rfind('/') {
                trimmed[..pos].to_string()
            } else {
                String::new()
            }
        } else {
            // No file extension, assume it's a directory path - keep it
            trimmed.to_string()
        }
    };

    format!("{}{}", origin, base_path)
}

impl WorkerClient {
    /// Create a new worker client
    pub fn new() -> Result<Self, JsValue> {
        // Create worker from inline script using Blob URL
        let base_url = get_base_url();
        let script = create_worker_script(&base_url);
        let blob_parts = Array::new();
        blob_parts.push(&JsValue::from_str(&script));

        let options = BlobPropertyBag::new();
        options.set_type("application/javascript");

        let blob = Blob::new_with_str_sequence_and_options(&blob_parts, &options)?;
        let url = Url::create_object_url_with_blob(&blob)?;

        let worker_options = web_sys::WorkerOptions::new();
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
            let msg = event.message();
            if !msg.is_empty() {
                log::error!("Worker error: {}", msg);
            } else {
                log::error!("Worker error (no message)");
            }
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);

        worker.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        Ok(Self {
            worker,
            pending_requests,
            next_id: Rc::new(RefCell::new(0)),
        })
    }

    /// Request database unlock in the worker (uses fast parallel argon2 with SIMD+pthread)
    pub fn unlock<F>(&self, data: Vec<u8>, password: String, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        self.unlock_internal(data, password, "unlock_fast", callback);
    }

    /// Request database unlock using SIMD-only argon2 (no pthreads)
    /// Use this for high-memory databases (>=1GB) where pthread deadlocks
    /// Still faster than single-threaded rust-argon2 due to SIMD
    #[allow(dead_code)]
    pub fn unlock_simd<F>(&self, data: Vec<u8>, password: String, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        self.unlock_internal(data, password, "unlock_fast_simd", callback);
    }

    /// Request database unlock using standard single-threaded Rust argon2
    /// Slowest option, but most reliable fallback
    pub fn unlock_standard<F>(&self, data: Vec<u8>, password: String, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        self.unlock_internal(data, password, "unlock", callback);
    }

    fn unlock_internal<F>(&self, data: Vec<u8>, password: String, unlock_type: &str, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        let id = {
            let mut next = self.next_id.borrow_mut();
            let id = *next;
            *next += 1;
            id
        };

        // Store the callback
        self.pending_requests
            .borrow_mut()
            .insert(id, Box::new(callback));

        // Create the message object
        let message = Object::new();
        Reflect::set(&message, &"type".into(), &unlock_type.into()).unwrap();
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

    /// Decrypt database with a pre-computed derived key (from parallel argon2)
    pub fn decrypt_with_key<F>(&self, data: Vec<u8>, password: String, derived_key: Vec<u8>, callback: F)
    where
        F: FnOnce(Result<UnlockResult, String>) + 'static,
    {
        let id = {
            let mut next = self.next_id.borrow_mut();
            let id = *next;
            *next += 1;
            id
        };

        // Store the callback
        self.pending_requests
            .borrow_mut()
            .insert(id, Box::new(callback));

        // Create the message object
        let message = Object::new();
        Reflect::set(&message, &"type".into(), &"decrypt_with_key".into()).unwrap();
        Reflect::set(&message, &"id".into(), &JsValue::from_f64(id as f64)).unwrap();

        // Create payload
        let payload = Object::new();

        let data_array = Uint8Array::from(data.as_slice());
        Reflect::set(&payload, &"data".into(), &data_array).unwrap();
        Reflect::set(&payload, &"password".into(), &password.into()).unwrap();

        let key_array = Uint8Array::from(derived_key.as_slice());
        Reflect::set(&payload, &"derivedKey".into(), &key_array).unwrap();

        Reflect::set(&message, &"payload".into(), &payload).unwrap();

        // Create transfer array
        let transfer = Array::new();
        transfer.push(&data_array.buffer());
        transfer.push(&key_array.buffer());

        if let Err(e) = self.worker.post_message_with_transfer(&message, &transfer) {
            log::error!("Failed to post decrypt message to worker: {:?}", e);
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
