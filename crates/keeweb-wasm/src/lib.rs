//! WASM bindings for keeweb-rs
//!
//! [`WasmDocument`] wraps the full-fidelity [`KdbxDocument`] together with the session
//! keys needed to save it. JavaScript callers exchange views, changes and outcomes as
//! JSON; Rust callers use the typed methods and the re-exported [`document`] types.

pub use kdbx_core::document;
pub use kdbx_core::{KdfParams, KdfType};

use kdbx_core::document::{Change, ChangeOutcome, KdbxDocument};
use kdbx_core::{TotpAlgorithm, TotpConfig};
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// A 32-byte key that is wiped from memory when dropped.
pub type Key = Zeroizing<[u8; 32]>;

/// Initialize panic hook for better error messages.
/// Call this function once at startup from your application.
#[allow(unexpected_cfgs)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

fn js_error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}

fn key_from_slice(bytes: &[u8], what: &str) -> Result<Key, String> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("The {what} must be 32 bytes"))?;
    Ok(Zeroizing::new(array))
}

/// Serde errors can quote the offending input, which may be a secret, so only the
/// position is reported.
fn json_error(error: serde_json::Error) -> String {
    format!(
        "Invalid JSON at line {}, column {}",
        error.line(),
        error.column()
    )
}

fn parse_uuid(value: &str) -> Result<Uuid, JsValue> {
    Uuid::parse_str(value).map_err(|_| js_error("Invalid UUID"))
}

fn to_json(value: &impl Serialize) -> Result<String, JsValue> {
    serde_json::to_string(value).map_err(|error| js_error(error.to_string()))
}

// ============================================================================
// Key derivation
// ============================================================================

/// Argon2 parameters of a KDBX 4 file, read from its outer header.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct WasmKdfParams {
    inner: KdfParams,
}

#[wasm_bindgen]
impl WasmKdfParams {
    /// Rebuilds parameters that crossed a worker boundary as plain values.
    #[wasm_bindgen(constructor)]
    pub fn new(
        kdf_type: &str,
        salt: Vec<u8>,
        memory_kb: u64,
        iterations: u64,
        parallelism: u32,
        version: u32,
    ) -> Result<WasmKdfParams, JsValue> {
        let kdf_type = match kdf_type {
            "argon2d" => KdfType::Argon2d,
            "argon2id" => KdfType::Argon2id,
            other => return Err(js_error(format!("Unsupported KDF type: {other}"))),
        };
        Ok(Self {
            inner: KdfParams {
                kdf_type,
                salt,
                memory_kb,
                iterations,
                parallelism,
                version,
            },
        })
    }

    /// "argon2d" or "argon2id"
    #[wasm_bindgen(getter, js_name = kdfType)]
    pub fn kdf_type(&self) -> String {
        match self.inner.kdf_type {
            KdfType::Argon2d => "argon2d",
            KdfType::Argon2id => "argon2id",
        }
        .to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn salt(&self) -> Vec<u8> {
        self.inner.salt.clone()
    }

    #[wasm_bindgen(getter, js_name = memoryKb)]
    pub fn memory_kb(&self) -> u64 {
        self.inner.memory_kb
    }

    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> u64 {
        self.inner.iterations
    }

    #[wasm_bindgen(getter)]
    pub fn parallelism(&self) -> u32 {
        self.inner.parallelism
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.inner.version
    }
}

impl WasmKdfParams {
    pub fn params(&self) -> &KdfParams {
        &self.inner
    }
}

/// Composite key of a password-only database: SHA-256(SHA-256(password)).
pub fn composite_key(password: &str) -> Key {
    Zeroizing::new(kdbx_core::compute_composite_key(password))
}

/// Composite key of a password-only database, as input for an external Argon2.
#[wasm_bindgen(js_name = compositeKey)]
pub fn composite_key_js(password: &str) -> Vec<u8> {
    composite_key(password).to_vec()
}

/// Runs Argon2 with the file's parameters in this thread. This is the slow fallback
/// used when neither the native helper nor the SIMD/pthread build is usable.
pub fn derive_transformed_key(params: &KdfParams, composite_key: &[u8; 32]) -> Result<Key, String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let algorithm = match params.kdf_type {
        KdfType::Argon2d => Algorithm::Argon2d,
        KdfType::Argon2id => Algorithm::Argon2id,
    };
    let version = match params.version {
        0x10 => Version::V0x10,
        _ => Version::V0x13,
    };
    let memory_kb = u32::try_from(params.memory_kb)
        .map_err(|_| "The Argon2 memory size is too large".to_string())?;
    let iterations = u32::try_from(params.iterations)
        .map_err(|_| "The Argon2 iteration count is too large".to_string())?;
    let argon2_params = Params::new(memory_kb, iterations, params.parallelism, Some(32))
        .map_err(|error| format!("Invalid Argon2 parameters: {error}"))?;

    let mut transformed_key = Zeroizing::new([0u8; 32]);
    Argon2::new(algorithm, version, argon2_params)
        .hash_password_into(composite_key, &params.salt, transformed_key.as_mut())
        .map_err(|error| format!("Argon2 failed: {error}"))?;
    Ok(transformed_key)
}

/// Single-threaded Argon2 for workers. Returns the 32-byte transformed key.
#[wasm_bindgen(js_name = deriveTransformedKey)]
pub fn derive_transformed_key_js(
    params: &WasmKdfParams,
    composite_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let composite_key = key_from_slice(composite_key, "composite key").map_err(js_error)?;
    derive_transformed_key(&params.inner, &composite_key)
        .map(|key| key.to_vec())
        .map_err(js_error)
}

// ============================================================================
// Editable document
// ============================================================================

#[derive(Clone)]
struct SessionKeys {
    composite: Key,
    transformed: Key,
}

/// An unlocked KDBX 4 document plus the keys that encrypt it on save.
///
/// The keys never leave this object except through [`WasmDocument::composite_key`],
/// which exists so that another revision of the same file (possibly re-salted) can be
/// derived with the same password.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmDocument {
    document: KdbxDocument,
    keys: SessionKeys,
}

impl WasmDocument {
    /// Argon2 parameters from the outer header; nothing is decrypted.
    pub fn kdf_params(data: &[u8]) -> Result<WasmKdfParams, String> {
        KdbxDocument::kdf_request(data)
            .map(|inner| WasmKdfParams { inner })
            .map_err(|error| error.to_string())
    }

    pub fn open(
        data: &[u8],
        composite_key: &[u8; 32],
        transformed_key: &[u8; 32],
    ) -> Result<Self, String> {
        let document = KdbxDocument::open(data, composite_key, transformed_key)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            document,
            keys: SessionKeys {
                composite: Zeroizing::new(*composite_key),
                transformed: Zeroizing::new(*transformed_key),
            },
        })
    }

    /// Opens another revision of this file with this session's composite key and the
    /// transformed key derived from that revision's own KDF parameters.
    pub fn open_revision(&self, data: &[u8], transformed_key: &[u8; 32]) -> Result<Self, String> {
        Self::open(data, &self.keys.composite, transformed_key)
    }

    pub fn document(&self) -> &KdbxDocument {
        &self.document
    }

    pub fn composite_key(&self) -> &[u8; 32] {
        &self.keys.composite
    }

    pub fn apply(&mut self, change: Change) -> Result<ChangeOutcome, String> {
        self.document
            .apply(change)
            .map_err(|error| error.to_string())
    }

    /// Encrypts the document with the session keys and the file's existing KDF
    /// parameters.
    pub fn save(&self) -> Result<Vec<u8>, String> {
        self.document
            .save(&self.keys.composite, &self.keys.transformed)
            .map_err(|error| error.to_string())
    }

    /// Replaces this (local) document with the three-way merge of `base`, itself and
    /// `remote`. Returns the titles of items changed on both sides. The merged document
    /// keeps this document's outer header, so it still saves with this session's keys.
    pub fn merge(&mut self, base: &Self, remote: &Self) -> Result<Vec<String>, String> {
        let outcome = document::merge(&base.document, &self.document, &remote.document)
            .map_err(|error| error.to_string())?;
        self.document = outcome.document;
        Ok(outcome.conflicts)
    }
}

#[wasm_bindgen]
impl WasmDocument {
    /// Argon2 parameters from the outer header of `data`.
    #[wasm_bindgen(js_name = kdfParams)]
    pub fn kdf_params_js(data: &[u8]) -> Result<WasmKdfParams, JsValue> {
        Self::kdf_params(data).map_err(js_error)
    }

    /// Decrypts `data` with a transformed key computed from the composite key.
    #[wasm_bindgen(js_name = open)]
    pub fn open_js(
        data: &[u8],
        composite_key: &[u8],
        transformed_key: &[u8],
    ) -> Result<WasmDocument, JsValue> {
        let composite_key = key_from_slice(composite_key, "composite key").map_err(js_error)?;
        let transformed_key =
            key_from_slice(transformed_key, "transformed key").map_err(js_error)?;
        Self::open(data, &composite_key, &transformed_key).map_err(js_error)
    }

    /// Opens another revision of the same file, e.g. the server copy before a merge.
    #[wasm_bindgen(js_name = openRevision)]
    pub fn open_revision_js(
        &self,
        data: &[u8],
        transformed_key: &[u8],
    ) -> Result<WasmDocument, JsValue> {
        let transformed_key =
            key_from_slice(transformed_key, "transformed key").map_err(js_error)?;
        self.open_revision(data, &transformed_key).map_err(js_error)
    }

    /// Input for deriving the transformed key of another revision of this file.
    #[wasm_bindgen(js_name = compositeKey)]
    pub fn composite_key_bytes(&self) -> Vec<u8> {
        self.keys.composite.to_vec()
    }

    /// All entries (including the recycle bin) as JSON `EntryView[]`.
    #[wasm_bindgen(js_name = entries)]
    pub fn entries_json(&self) -> Result<String, JsValue> {
        to_json(&self.document.entries())
    }

    /// All groups, root first, as JSON `GroupView[]`.
    #[wasm_bindgen(js_name = groups)]
    pub fn groups_json(&self) -> Result<String, JsValue> {
        to_json(&self.document.groups())
    }

    /// Database settings as JSON `MetaView`.
    #[wasm_bindgen(js_name = meta)]
    pub fn meta_json(&self) -> Result<String, JsValue> {
        to_json(&self.document.meta())
    }

    /// Custom icons as JSON `CustomIconView[]`.
    #[wasm_bindgen(js_name = customIcons)]
    pub fn custom_icons_json(&self) -> Result<String, JsValue> {
        to_json(&self.document.custom_icons())
    }

    /// Content of attachment `name` of the current version of `entry`.
    #[wasm_bindgen(js_name = attachment)]
    pub fn attachment_js(&self, entry: &str, name: &str) -> Result<Option<Vec<u8>>, JsValue> {
        Ok(self.document.attachment(parse_uuid(entry)?, name))
    }

    /// Content of attachment `name` of history version `index` (oldest first) of `entry`.
    #[wasm_bindgen(js_name = historyAttachment)]
    pub fn history_attachment_js(
        &self,
        entry: &str,
        index: usize,
        name: &str,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        Ok(self
            .document
            .history_attachment(parse_uuid(entry)?, index, name))
    }

    /// Applies a JSON `Change` and returns the JSON `ChangeOutcome`.
    #[wasm_bindgen(js_name = apply)]
    pub fn apply_json(&mut self, change_json: &str) -> Result<String, JsValue> {
        let change: Change =
            serde_json::from_str(change_json).map_err(|error| js_error(json_error(error)))?;
        let outcome = self.apply(change).map_err(js_error)?;
        to_json(&outcome)
    }

    /// The encrypted KDBX 4 file.
    #[wasm_bindgen(js_name = save)]
    pub fn save_js(&self) -> Result<Vec<u8>, JsValue> {
        self.save().map_err(js_error)
    }

    /// An independent copy, e.g. to keep as the merge base.
    #[wasm_bindgen(js_name = snapshot)]
    pub fn snapshot(&self) -> WasmDocument {
        self.clone()
    }

    /// Merges `remote` into this document against their common ancestor `base`.
    /// Returns a JSON array of the titles of items changed on both sides.
    #[wasm_bindgen(js_name = merge)]
    pub fn merge_js(
        &mut self,
        base: &WasmDocument,
        remote: &WasmDocument,
    ) -> Result<String, JsValue> {
        let conflicts = self.merge(base, remote).map_err(js_error)?;
        to_json(&conflicts)
    }
}

// ============================================================================
// TOTP (Time-based One-Time Password) support
// ============================================================================

/// TOTP code result with metadata
#[wasm_bindgen]
pub struct TotpResult {
    code: String,
    period: u32,
    remaining: u32,
    digits: u32,
}

#[wasm_bindgen]
impl TotpResult {
    /// The generated TOTP code
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// The time period in seconds
    #[wasm_bindgen(getter)]
    pub fn period(&self) -> u32 {
        self.period
    }

    /// Seconds remaining until the code changes
    #[wasm_bindgen(getter)]
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Number of digits in the code
    #[wasm_bindgen(getter)]
    pub fn digits(&self) -> u32 {
        self.digits
    }
}

/// Generate a TOTP code from an OTP configuration string
///
/// Accepts:
/// - otpauth://totp/... URI format (KeePassXC standard)
/// - Bare base32 secret (uses defaults: SHA1, 6 digits, 30s period)
///
/// Returns a TotpResult with the code and metadata, or an error message.
#[wasm_bindgen(js_name = generateTotp)]
pub fn generate_totp(otp_value: &str) -> Result<TotpResult, JsValue> {
    let config = TotpConfig::parse(otp_value).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let code = config
        .generate()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(TotpResult {
        code,
        period: config.period,
        remaining: config.time_remaining(),
        digits: config.digits,
    })
}

/// Parse a TOTP configuration and return its details as JSON
///
/// Returns JSON with: secret, digits, period, algorithm, issuer, label
#[wasm_bindgen(js_name = parseTotpConfig)]
pub fn parse_totp_config(otp_value: &str) -> Result<String, JsValue> {
    let config = TotpConfig::parse(otp_value).map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct TotpConfigJson {
        digits: u32,
        period: u32,
        algorithm: String,
        issuer: Option<String>,
        label: Option<String>,
    }

    let json = TotpConfigJson {
        digits: config.digits,
        period: config.period,
        algorithm: match config.algorithm {
            TotpAlgorithm::Sha1 => "SHA1".to_string(),
            TotpAlgorithm::Sha256 => "SHA256".to_string(),
            TotpAlgorithm::Sha512 => "SHA512".to_string(),
        },
        issuer: config.issuer,
        label: config.label,
    };

    serde_json::to_string(&json).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Check if a string looks like a valid TOTP configuration
#[wasm_bindgen(js_name = isValidTotp)]
pub fn is_valid_totp(otp_value: &str) -> bool {
    TotpConfig::parse(otp_value).is_ok()
}
