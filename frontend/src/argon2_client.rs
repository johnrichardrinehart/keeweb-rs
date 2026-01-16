//! Argon2 pthread client for parallel key derivation
//!
//! This runs the @very-amused/argon2-wasm worker directly from the main thread
//! to enable true multi-threaded Argon2 with SharedArrayBuffer.

use js_sys::{Object, Reflect, Uint8Array};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, Worker};

/// Callback type for argon2 completion
type Argon2Callback = Box<dyn FnOnce(Result<Vec<u8>, String>)>;

/// Argon2 Methods enum (matches @very-amused/argon2-wasm)
#[repr(u32)]
enum Argon2Method {
    LoadArgon2 = 0,
    _Hash2i = 1,
    Hash2d = 2,
    Hash2id = 3,
}

/// Client for communicating with the argon2-pthread worker
/// Note: The argon2-pthread worker doesn't echo back request IDs,
/// so we use a queue to match responses to callbacks in order.
pub struct Argon2Client {
    worker: Worker,
    pending_callbacks: Rc<RefCell<VecDeque<Argon2Callback>>>,
    ready: Rc<RefCell<bool>>,
}

impl Argon2Client {
    /// Create a new argon2 client and initialize the worker
    pub fn new() -> Result<Self, JsValue> {
        log::debug!("Creating argon2-pthread client");

        // Get base URL for worker path
        let window = web_sys::window().ok_or("No window")?;
        let location = window.location();
        let origin = location.origin()?;

        let worker_url = format!("{}/argon2-pthread/build/worker.min.js", origin);
        log::debug!("Loading argon2-pthread worker from: {}", worker_url);

        let worker = Worker::new(&worker_url)?;

        let pending_callbacks: Rc<RefCell<VecDeque<Argon2Callback>>> =
            Rc::new(RefCell::new(VecDeque::new()));
        let pending_clone = pending_callbacks.clone();
        let ready = Rc::new(RefCell::new(false));
        let ready_clone = ready.clone();

        // Set up message handler
        // Note: argon2-pthread doesn't echo back IDs, so we use a queue
        let onmessage = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();

            let code = Reflect::get(&data, &"code".into())
                .ok()
                .and_then(|v| v.as_f64())
                .map(|v| v as i32)
                .unwrap_or(-1);

            log::debug!("Argon2 message received: code={}", code);

            // Pop the next callback from the queue
            let callback = pending_clone.borrow_mut().pop_front();

            if let Some(callback) = callback {
                if code == 0 {
                    // Success - extract hash from body
                    let body = Reflect::get(&data, &"body".into()).ok();
                    if let Some(body) = body {
                        if body.is_undefined() {
                            // Load success (no body) - mark as ready
                            log::debug!("Argon2 module loaded successfully");
                            *ready_clone.borrow_mut() = true;
                            callback(Ok(vec![]));
                        } else {
                            let arr = Uint8Array::new(&body);
                            let mut hash = vec![0u8; arr.length() as usize];
                            arr.copy_to(&mut hash);
                            log::debug!("Argon2 hash computed, {} bytes", hash.len());
                            callback(Ok(hash));
                        }
                    } else {
                        // Load success (no body)
                        log::debug!("Argon2 module loaded successfully (no body)");
                        *ready_clone.borrow_mut() = true;
                        callback(Ok(vec![]));
                    }
                } else {
                    let message = Reflect::get(&data, &"message".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_else(|| format!("Argon2 error code: {}", code));
                    log::error!("Argon2 error: {}", message);
                    callback(Err(message));
                }
            } else {
                log::warn!("Argon2 response received but no pending callback");
            }
        }) as Box<dyn FnMut(MessageEvent)>);

        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        onmessage.forget();

        // Set up error handler
        let onerror = Closure::wrap(Box::new(move |event: web_sys::ErrorEvent| {
            log::error!("Argon2 worker error: {:?}", event.message());
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);

        worker.set_onerror(Some(onerror.as_ref().unchecked_ref()));
        onerror.forget();

        let client = Self {
            worker,
            pending_callbacks,
            ready,
        };

        Ok(client)
    }

    /// Initialize the argon2 WASM module with SIMD and pthread support
    pub fn init<F>(&self, callback: F)
    where
        F: FnOnce(Result<(), String>) + 'static,
    {
        log::debug!("Initializing argon2-pthread with SIMD and threading");

        // Store callback in queue
        self.pending_callbacks.borrow_mut().push_back(Box::new(move |result| {
            callback(result.map(|_| ()));
        }));

        // Get base URL
        let origin = web_sys::window()
            .and_then(|w| w.location().origin().ok())
            .unwrap_or_default();

        // Create load message
        let message = Object::new();
        Reflect::set(
            &message,
            &"method".into(),
            &JsValue::from_f64(Argon2Method::LoadArgon2 as u32 as f64),
        )
        .unwrap();

        let params = Object::new();
        Reflect::set(
            &params,
            &"wasmRoot".into(),
            &format!("{}/argon2-pthread/build", origin).into(),
        )
        .unwrap();
        Reflect::set(&params, &"simd".into(), &JsValue::TRUE).unwrap();
        Reflect::set(&params, &"pthread".into(), &JsValue::TRUE).unwrap();

        Reflect::set(&message, &"params".into(), &params).unwrap();

        if let Err(e) = self.worker.post_message(&message) {
            log::error!("Failed to send init message: {:?}", e);
            if let Some(cb) = self.pending_callbacks.borrow_mut().pop_back() {
                cb(Err(format!("Failed to init: {:?}", e)));
            }
        }
    }

    /// Run Argon2 hash with the given parameters
    pub fn hash<F>(
        &self,
        argon2_type: &str, // "argon2d" or "argon2id"
        password: Vec<u8>,
        salt: Vec<u8>,
        time_cost: u32,
        memory_cost: u32,
        threads: u32,
        hash_len: u32,
        callback: F,
    ) where
        F: FnOnce(Result<Vec<u8>, String>) + 'static,
    {
        log::debug!(
            "Running Argon2 {} with {} threads, mem={}KB, iter={}",
            argon2_type,
            threads,
            memory_cost,
            time_cost
        );

        // Store callback in queue
        self.pending_callbacks.borrow_mut().push_back(Box::new(callback));

        // Select method based on type
        let method = if argon2_type == "argon2d" {
            Argon2Method::Hash2d
        } else {
            Argon2Method::Hash2id
        };

        // Create hash message
        let message = Object::new();
        Reflect::set(
            &message,
            &"method".into(),
            &JsValue::from_f64(method as u32 as f64),
        )
        .unwrap();

        let params = Object::new();

        // Password as Uint8Array (patched worker now accepts binary data directly)
        let pass_arr = Uint8Array::from(password.as_slice());
        Reflect::set(&params, &"password".into(), &pass_arr).unwrap();

        // Salt as Uint8Array
        let salt_arr = Uint8Array::from(salt.as_slice());
        Reflect::set(&params, &"salt".into(), &salt_arr).unwrap();

        Reflect::set(&params, &"timeCost".into(), &JsValue::from_f64(time_cost as f64)).unwrap();
        Reflect::set(&params, &"memoryCost".into(), &JsValue::from_f64(memory_cost as f64)).unwrap();
        Reflect::set(&params, &"threads".into(), &JsValue::from_f64(threads as f64)).unwrap();
        Reflect::set(&params, &"hashLen".into(), &JsValue::from_f64(hash_len as f64)).unwrap();

        Reflect::set(&message, &"params".into(), &params).unwrap();

        if let Err(e) = self.worker.post_message(&message) {
            log::error!("Failed to send hash message: {:?}", e);
            if let Some(cb) = self.pending_callbacks.borrow_mut().pop_back() {
                cb(Err(format!("Failed to hash: {:?}", e)));
            }
        }
    }

    /// Check if the worker is ready
    pub fn is_ready(&self) -> bool {
        *self.ready.borrow()
    }
}
