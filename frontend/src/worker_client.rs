//! Web Worker that derives transformed keys off the main thread.
//!
//! The worker runs Argon2 either through its own argon2-pthread instance (SIMD and
//! threads) or, as the slow fallback, through the single-threaded Rust implementation
//! exported by keeweb-wasm. It never sees the database contents.

use js_sys::{Array, Object, Reflect, Uint8Array};
use keeweb_wasm::WasmKdfParams;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{Blob, BlobPropertyBag, MessageEvent, Url, Worker};

/// Callback receiving the 32-byte transformed key.
type KeyCallback = Box<dyn FnOnce(Result<Vec<u8>, String>)>;

/// Client for communicating with the key derivation worker
pub struct WorkerClient {
    worker: Worker,
    pending_requests: Rc<RefCell<HashMap<u32, KeyCallback>>>,
    next_id: Cell<u32>,
}

/// Generate worker script that can load WASM dynamically
fn create_worker_script(base_url: &str) -> String {
    // Base URL is injected to handle subpath deployments (e.g., GitHub Pages)
    let mut script = String::from(
        r#"
// Web Worker for KeeWeb-RS key derivation.
const BASE_URL = ""#,
    );
    script.push_str(base_url);
    script.push_str(
        r#"";

let keewebWasm = null;
let argon2Worker = null;
let argon2Ready = false;

// argon2-pthread does not echo request ids, so responses are matched in order.
let argon2PendingQueue = [];

// Argon2 Methods enum (from @very-amused/argon2-wasm)
const Argon2Methods = {
    LoadArgon2: 0,
    Hash2i: 1,
    Hash2d: 2,
    Hash2id: 3,
    Unload: 4
};

async function initArgon2Worker() {
    return new Promise((resolve, reject) => {
        argon2Worker = new Worker(BASE_URL + '/argon2-pthread/build/worker.js');

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

        argon2PendingQueue.push({ resolve, reject });
        argon2Worker.postMessage({
            method: Argon2Methods.LoadArgon2,
            params: {
                wasmRoot: BASE_URL + '/argon2-pthread/build',
                simd: true,
                pthread: true
            }
        });
    });
}

async function runArgon2(kdfType, password, salt, timeCost, memoryCost, threads) {
    if (!argon2Ready) {
        await initArgon2Worker();
        argon2Ready = true;
    }
    return new Promise((resolve, reject) => {
        argon2PendingQueue.push({ resolve, reject });
        argon2Worker.postMessage({
            method: kdfType === 'argon2d' ? Argon2Methods.Hash2d : Argon2Methods.Hash2id,
            params: { password, salt, timeCost, memoryCost, threads, hashLen: 32 }
        });
    });
}

async function initKeewebWasm() {
    if (keewebWasm) return;
    const module = await import(BASE_URL + '/wasm/keeweb_wasm.js');
    await module.default({ module_or_path: BASE_URL + '/wasm/keeweb_wasm_bg.wasm' });
    keewebWasm = module;
}

// Single-threaded Rust Argon2 from keeweb-wasm.
async function deriveStandard(p) {
    await initKeewebWasm();
    const params = new keewebWasm.WasmKdfParams(
        p.kdfType, p.salt, BigInt(p.memoryKb), BigInt(p.iterations), p.parallelism, p.version
    );
    try {
        return keewebWasm.deriveTransformedKey(params, p.compositeKey);
    } finally {
        params.free();
    }
}

async function deriveFast(p) {
    try {
        // The argon2 worker wipes the buffers it receives, so hand it copies.
        const hash = await runArgon2(
            p.kdfType, p.compositeKey.slice(), p.salt.slice(),
            p.iterations, p.memoryKb, p.parallelism
        );
        return new Uint8Array(hash);
    } catch (e) {
        return await deriveStandard(p);
    }
}

self.onmessage = async function(event) {
    const { type, id, payload } = event.data;
    try {
        let key;
        switch (type) {
            case 'derive':
                key = await deriveStandard(payload);
                break;
            case 'derive_fast':
                key = await deriveFast(payload);
                break;
            default:
                throw new Error('Unknown message type: ' + type);
        }
        self.postMessage({ id, type: 'key', key }, [key.buffer]);
    } catch (e) {
        self.postMessage({
            id,
            type: 'error',
            error: e ? (e.message || e.toString()) : 'Unknown error'
        });
    } finally {
        if (payload && payload.compositeKey) {
            payload.compositeKey.fill(0);
        }
    }
};
"#,
    );
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

        let pending_requests: Rc<RefCell<HashMap<u32, KeyCallback>>> =
            Rc::new(RefCell::new(HashMap::new()));
        let pending_clone = pending_requests.clone();

        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();

            let id = Reflect::get(&data, &"id".into())
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as u32);
            let msg_type = Reflect::get(&data, &"type".into())
                .ok()
                .and_then(|v| v.as_string());

            let (Some(id), Some(msg_type)) = (id, msg_type) else {
                return;
            };
            let Some(callback) = pending_clone.borrow_mut().remove(&id) else {
                return;
            };
            match msg_type.as_str() {
                "key" => match Reflect::get(&data, &"key".into()) {
                    Ok(key) if key.is_instance_of::<Uint8Array>() => {
                        let array = Uint8Array::new(&key);
                        let mut bytes = vec![0u8; array.length() as usize];
                        array.copy_to(&mut bytes);
                        array.fill(0, 0, array.length());
                        callback(Ok(bytes));
                    }
                    _ => callback(Err("The key worker returned no key".to_string())),
                },
                _ => {
                    let error = Reflect::get(&data, &"error".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_else(|| "Unknown error".to_string());
                    callback(Err(error));
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);

        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

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
            next_id: Cell::new(0),
        })
    }

    /// Derive the transformed key in the worker. `fast` uses the SIMD/pthread Argon2
    /// and falls back to the single-threaded Rust implementation on failure.
    pub fn derive_key<F>(
        &self,
        params: &WasmKdfParams,
        composite_key: &[u8; 32],
        fast: bool,
        callback: F,
    ) where
        F: FnOnce(Result<Vec<u8>, String>) + 'static,
    {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        self.pending_requests
            .borrow_mut()
            .insert(id, Box::new(callback));

        let payload = Object::new();
        let composite_array = Uint8Array::from(composite_key.as_slice());
        let salt_array = Uint8Array::from(params.salt().as_slice());
        let fields: [(&str, JsValue); 7] = [
            ("kdfType", params.kdf_type().into()),
            ("salt", salt_array.clone().into()),
            ("memoryKb", JsValue::from_f64(params.memory_kb() as f64)),
            ("iterations", JsValue::from_f64(params.iterations() as f64)),
            ("parallelism", params.parallelism().into()),
            ("version", params.version().into()),
            ("compositeKey", composite_array.clone().into()),
        ];
        for (name, value) in fields {
            let _ = Reflect::set(&payload, &name.into(), &value);
        }

        let message = Object::new();
        let message_type = if fast { "derive_fast" } else { "derive" };
        let _ = Reflect::set(&message, &"type".into(), &message_type.into());
        let _ = Reflect::set(&message, &"id".into(), &JsValue::from_f64(id as f64));
        let _ = Reflect::set(&message, &"payload".into(), &payload);

        // Transferring detaches the buffers here, so the composite key copy does not
        // linger in this thread's JS heap.
        let transfer = Array::new();
        transfer.push(&composite_array.buffer());
        transfer.push(&salt_array.buffer());

        if let Err(e) = self.worker.post_message_with_transfer(&message, &transfer) {
            log::error!("Failed to post message to worker: {:?}", e);
            if let Some(callback) = self.pending_requests.borrow_mut().remove(&id) {
                callback(Err("Failed to start the key derivation worker".to_string()));
            }
        }
    }
}
