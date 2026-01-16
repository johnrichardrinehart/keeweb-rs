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
    // The worker script as a string - loads keeweb-wasm and uses @very-amused/argon2-wasm for pthread support
    // Uses dynamic import() for ES modules since we're a module worker
    r#"
// Web Worker for KeeWeb-RS database operations
// Uses @very-amused/argon2-wasm with pthread support for fast parallel key derivation

let wasmModule = null;
let argon2Worker = null;
let argon2Ready = false;
let getKdfParams = null;
let decryptWithDerivedKey = null;
let WasmDatabase = null;

// Message ID counter for argon2 worker
let argon2MsgId = 0;
let argon2Pending = new Map();

// Argon2 Methods enum (from @very-amused/argon2-wasm)
const Argon2Methods = {
    LoadArgon2: 0,
    Hash2i: 1,
    Hash2d: 2,
    Hash2id: 3,
    Unload: 4
};

// Initialize argon2 worker with pthread support
async function initArgon2Worker(baseUrl) {
    return new Promise((resolve, reject) => {
        const workerUrl = baseUrl + '/argon2-pthread/build/worker.min.js';
        console.log('[Worker] Loading argon2-pthread worker from:', workerUrl);

        argon2Worker = new Worker(workerUrl);

        argon2Worker.onmessage = (event) => {
            const { id, code, body } = event.data;
            const pending = argon2Pending.get(id);
            if (pending) {
                argon2Pending.delete(id);
                if (code === 0) {
                    pending.resolve(body);
                } else {
                    pending.reject(new Error('Argon2 error code: ' + code));
                }
            }
        };

        argon2Worker.onerror = (e) => {
            console.error('[Worker] Argon2 worker error:', e);
            reject(e);
        };

        // Load argon2 WASM with SIMD and pthread support
        const loadId = argon2MsgId++;
        argon2Pending.set(loadId, { resolve, reject });

        argon2Worker.postMessage({
            id: loadId,
            method: Argon2Methods.LoadArgon2,
            params: {
                wasmRoot: baseUrl + '/argon2-pthread/build',
                simd: true,
                pthread: true
            }
        });
    });
}

// Run argon2 hash via the pthread worker
async function runArgon2(type, password, salt, timeCost, memoryCost, threads, hashLen) {
    return new Promise((resolve, reject) => {
        const id = argon2MsgId++;
        argon2Pending.set(id, { resolve, reject });

        // Select method based on type (0=2d, 2=2id)
        const method = type === 0 ? Argon2Methods.Hash2d : Argon2Methods.Hash2id;

        argon2Worker.postMessage({
            id,
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

    const baseUrl = self.location.origin;

    try {
        const jsUrl = baseUrl + '/wasm/keeweb_wasm.js';
        const wasmUrl = baseUrl + '/wasm/keeweb_wasm_bg.wasm';
        console.log('[Worker] Loading keeweb-wasm from:', jsUrl);

        const module = await import(jsUrl);
        wasmModule = await module.default(wasmUrl);

        getKdfParams = module.getKdfParams;
        decryptWithDerivedKey = module.decryptWithDerivedKey;
        WasmDatabase = module.WasmDatabase;
        console.log('[Worker] keeweb-wasm loaded');
    } catch (e) {
        console.error('[Worker] Failed to load keeweb-wasm:', e);
        throw e;
    }
}

// Initialize WASM modules including argon2 (for unlock_fast)
async function initWasm() {
    if (wasmModule && argon2Ready) return;

    const baseUrl = self.location.origin;

    try {
        // Load keeweb-wasm first
        await initKeewebWasm();

        // Load argon2 pthread worker
        if (!argon2Ready) {
            console.log('[Worker] Loading argon2-pthread with SIMD and threading...');
            await initArgon2Worker(baseUrl);
            argon2Ready = true;
            console.log('[Worker] argon2-pthread loaded (SIMD + pthreads enabled)');
        }
    } catch (e) {
        console.error('[Worker] Failed to initialize:', e);
        throw e;
    }
}

// Handle messages from main thread
self.onmessage = async function(event) {
    const { type, id, payload } = event.data;
    console.log('[Worker] Received message:', type, 'id:', id);

    try {
        switch (type) {
            case 'unlock':
                // Standard unlock - needs keeweb-wasm only
                await initKeewebWasm();
                await handleUnlock(id, payload);
                break;
            case 'unlock_fast':
                // Fast unlock - needs both keeweb-wasm and argon2
                await initWasm();
                await handleUnlockFast(id, payload);
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
        console.error('[Worker] Error handling message:', e);
        self.postMessage({
            id,
            type: 'error',
            error: e.toString()
        });
    }
};

// Fast unlock using argon2-pthread with SIMD and multi-threading
async function handleUnlockFast(id, { data, password }) {
    console.log('[Worker] Starting FAST unlock (argon2-pthread SIMD+threads), data size:', data.length);

    try {
        // Verify argon2 worker is ready
        if (!argon2Ready) {
            throw new Error('Argon2 worker not ready');
        }

        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);
        const totalStart = performance.now();

        // Step 1: Extract KDF parameters from KDBX header
        console.log('[Worker] Extracting KDF parameters...');
        const kdfStart = performance.now();
        const kdfParams = getKdfParams(dataArray, password);
        console.log('[Worker] KDF params extracted in', (performance.now() - kdfStart).toFixed(0), 'ms');
        console.log('[Worker] KDF:', kdfParams.kdfType, 'mem:', kdfParams.memoryKb, 'KB, iter:', kdfParams.iterations, ', parallel:', kdfParams.parallelism);

        // Step 2: Run Argon2 with SIMD and pthreads
        console.log('[Worker] Running Argon2 with', kdfParams.parallelism, 'threads (SIMD+pthread)...');
        const argon2Start = performance.now();

        // argon2 type values: 0=Argon2d, 2=Argon2id
        const argon2Type = kdfParams.kdfType === 'argon2d' ? 0 : 2;
        console.log('[Worker] Argon2 type:', argon2Type, '(0=d, 2=id)');

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

        const argon2Elapsed = performance.now() - argon2Start;
        console.log('[Worker] Argon2 SIMD completed in', argon2Elapsed.toFixed(0), 'ms');

        // Step 3: Decrypt database with derived key
        console.log('[Worker] Decrypting database...');
        const decryptStart = performance.now();
        const decryptResult = decryptWithDerivedKey(dataArray, password, argon2Result.hash);
        console.log('[Worker] Decryption completed in', (performance.now() - decryptStart).toFixed(0), 'ms');

        const totalElapsed = performance.now() - totalStart;
        console.log('[Worker] FAST unlock total:', totalElapsed.toFixed(0), 'ms');

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
        console.error('[Worker] Fast unlock failed:', e);
        console.log('[Worker] Falling back to standard unlock...');
        // Fall back to standard unlock
        await handleUnlock(id, { data, password });
    }
}

// Standard unlock (fallback, uses rust-argon2)
async function handleUnlock(id, { data, password }) {
    console.log('[Worker] Starting STANDARD unlock, data size:', data.length);

    try {
        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);

        console.log('[Worker] Opening database (rust-argon2)...');
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

// Decrypt with pre-computed key (from main thread parallel argon2)
async function handleDecryptWithKey(id, { data, password, derivedKey }) {
    console.log('[Worker] Decrypting with pre-computed key, data size:', data.length, 'key size:', derivedKey.length);

    try {
        const dataArray = data instanceof Uint8Array ? data : new Uint8Array(data);
        const keyArray = derivedKey instanceof Uint8Array ? derivedKey : new Uint8Array(derivedKey);

        const startTime = performance.now();

        // Use the decryptWithDerivedKey function from keeweb-wasm
        const decryptResult = decryptWithDerivedKey(dataArray, password, keyArray);

        const elapsed = performance.now() - startTime;
        console.log('[Worker] Decryption completed in', elapsed.toFixed(0), 'ms');

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
        console.error('[Worker] Decrypt with key failed:', e);
        self.postMessage({
            id,
            type: 'unlock_error',
            error: e.toString()
        });
    }
}

console.log('[Worker] Worker script loaded (with parallel argon2 support)');
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

        // Create the message object - use unlock_fast for argon2-browser SIMD
        let message = Object::new();
        Reflect::set(&message, &"type".into(), &"unlock_fast".into()).unwrap();
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

        log::debug!("Sending decrypt_with_key request, id={}, data_len={}, key_len={}", id, data.len(), derived_key.len());

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
