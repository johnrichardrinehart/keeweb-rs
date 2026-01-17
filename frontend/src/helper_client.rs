//! Helper server client for offloading heavy computations
//!
//! This module provides a client to communicate with the optional keeweb-server
//! for native-speed Argon2 computation when browser-based computation is too slow.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

/// Request body for the /api/argon2 endpoint
#[derive(Debug, Serialize)]
struct Argon2Request {
    /// Base64-encoded password bytes
    password: String,
    /// Base64-encoded salt
    salt: String,
    /// Memory cost in KiB
    memory_kib: u32,
    /// Time cost (iterations)
    iterations: u32,
    /// Parallelism (lanes)
    parallelism: u32,
    /// Output length in bytes
    output_len: usize,
    /// Argon2 variant: "d", "i", or "id"
    variant: String,
    /// Argon2 version: 16 (0x10) or 19 (0x13)
    version: u32,
}

/// Response from the /api/argon2 endpoint
#[derive(Debug, Deserialize)]
struct Argon2Response {
    /// Base64-encoded derived key
    hash: String,
    /// Time taken in milliseconds
    time_ms: u64,
}

/// Error response from the helper server
#[derive(Debug, Deserialize)]
struct Argon2Error {
    error: String,
}

/// Client for communicating with the helper server
pub struct HelperClient {
    base_url: String,
}

impl HelperClient {
    /// Create a new helper client with the given base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// Check if the helper server is available
    pub async fn health_check(&self) -> Result<bool, String> {
        let url = format!("{}/health", self.base_url);

        let window = web_sys::window().ok_or("No window object")?;

        let opts = RequestInit::new();
        opts.set_method("GET");
        opts.set_mode(RequestMode::Cors);

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|_| "Failed to create request".to_string())?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|_| "Fetch failed".to_string())?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| "Response is not a Response object".to_string())?;

        Ok(resp.ok())
    }

    /// Compute Argon2 hash using the helper server
    ///
    /// This runs natively on the server and is much faster than WebAssembly
    /// for high-memory configurations.
    pub async fn argon2_hash(
        &self,
        variant: &str,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
        output_len: usize,
        version: u32,
    ) -> Result<(Vec<u8>, u64), String> {
        let url = format!("{}/api/argon2", self.base_url);

        let request_body = Argon2Request {
            password: BASE64.encode(password),
            salt: BASE64.encode(salt),
            memory_kib,
            iterations,
            parallelism,
            output_len,
            variant: variant.to_string(),
            version,
        };

        let body = serde_json::to_string(&request_body)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        let window = web_sys::window().ok_or("No window object")?;

        let opts = RequestInit::new();
        opts.set_method("POST");
        opts.set_mode(RequestMode::Cors);
        opts.set_body(&JsValue::from_str(&body));

        let request = Request::new_with_str_and_init(&url, &opts)
            .map_err(|e| format!("Failed to create request: {:?}", e))?;

        request
            .headers()
            .set("Content-Type", "application/json")
            .map_err(|e| format!("Failed to set header: {:?}", e))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| format!("Fetch failed: {:?}", e))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| "Response is not a Response object")?;

        let json = JsFuture::from(
            resp.json()
                .map_err(|e| format!("Failed to get JSON: {:?}", e))?,
        )
        .await
        .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;

        if resp.ok() {
            let response: Argon2Response = serde_wasm_bindgen::from_value(json)
                .map_err(|e| format!("Failed to deserialize response: {}", e))?;

            let hash = BASE64
                .decode(&response.hash)
                .map_err(|e| format!("Failed to decode hash: {}", e))?;

            Ok((hash, response.time_ms))
        } else {
            let error: Argon2Error = serde_wasm_bindgen::from_value(json)
                .map_err(|e| format!("Failed to deserialize error: {}", e))?;

            Err(error.error)
        }
    }
}

thread_local! {
    static HELPER_CLIENT: std::cell::RefCell<Option<HelperClient>> = const { std::cell::RefCell::new(None) };
    static HELPER_AVAILABLE: std::cell::RefCell<Option<bool>> = const { std::cell::RefCell::new(None) };
}

/// Configure the helper server URL
pub fn configure_helper(url: impl Into<String>) {
    let url = url.into();
    HELPER_CLIENT.with(|client| {
        *client.borrow_mut() = Some(HelperClient::new(url));
    });
    HELPER_AVAILABLE.with(|available| {
        *available.borrow_mut() = None;
    });
}

/// Check if helper is configured
pub fn is_helper_configured() -> bool {
    HELPER_CLIENT.with(|client| client.borrow().is_some())
}

/// Check if helper server is available (synchronous, returns cached result)
/// Returns true only if we've successfully connected to the helper
pub fn is_helper_available() -> bool {
    HELPER_AVAILABLE.with(|available| available.borrow().unwrap_or(false))
}

/// Check if helper server is available (async)
pub async fn check_helper_available() -> Result<bool, String> {
    // Return cached result if available
    let cached = HELPER_AVAILABLE.with(|available| *available.borrow());
    if let Some(available) = cached {
        return Ok(available);
    }

    // Check if client is configured
    let client_exists = HELPER_CLIENT.with(|client| client.borrow().is_some());
    if !client_exists {
        return Ok(false);
    }

    // Perform health check
    let result = HELPER_CLIENT.with(|client| {
        if let Some(ref c) = *client.borrow() {
            let url = c.base_url.clone();
            Some(url)
        } else {
            None
        }
    });

    if let Some(url) = result {
        let client = HelperClient::new(url);
        match client.health_check().await {
            Ok(available) => {
                HELPER_AVAILABLE.with(|a| *a.borrow_mut() = Some(available));
                Ok(available)
            }
            Err(_) => {
                HELPER_AVAILABLE.with(|a| *a.borrow_mut() = Some(false));
                Ok(false)
            }
        }
    } else {
        Ok(false)
    }
}

/// Default helper server URL
pub const DEFAULT_HELPER_URL: &str = "http://127.0.0.1:8081";

/// Attempt to auto-connect to the default helper server
/// Returns true if connection was successful
pub async fn try_auto_connect() -> bool {
    let client = HelperClient::new(DEFAULT_HELPER_URL);
    match client.health_check().await {
        Ok(true) => {
            configure_helper(DEFAULT_HELPER_URL);
            HELPER_AVAILABLE.with(|a| *a.borrow_mut() = Some(true));
            true
        }
        _ => false,
    }
}

/// Disable the helper server
pub fn disable_helper() {
    HELPER_CLIENT.with(|client| {
        *client.borrow_mut() = None;
    });
    HELPER_AVAILABLE.with(|available| {
        *available.borrow_mut() = Some(false);
    });
}

/// Get the currently configured helper URL (if any)
pub fn get_helper_url() -> Option<String> {
    HELPER_CLIENT.with(|client| {
        client.borrow().as_ref().map(|c| c.base_url.clone())
    })
}

/// Compute Argon2 hash using the helper server (if available)
pub async fn helper_argon2_hash(
    variant: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
    output_len: usize,
    version: u32,
) -> Result<(Vec<u8>, u64), String> {
    let url = HELPER_CLIENT.with(|client| {
        client
            .borrow()
            .as_ref()
            .map(|c| c.base_url.clone())
    });

    match url {
        Some(url) => {
            let client = HelperClient::new(url);
            let result = client
                .argon2_hash(variant, password, salt, iterations, memory_kib, parallelism, output_len, version)
                .await;

            result
        }
        None => Err("Helper server not configured".to_string()),
    }
}
