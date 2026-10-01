//! Fingerprint quick unlock through the WebAuthn PRF extension.
//!
//! Enrollment creates a platform credential (Touch ID, Windows Hello, Android biometrics)
//! for one vault and evaluates its PRF with a random salt. HKDF-SHA-256 turns the PRF
//! output into a non-extractable AES-256-GCM key that encrypts the vault's composite key
//! and transformed key. IndexedDB keeps, per vault key,
//! `{credentialId, prfSalt, iv, ciphertext, kdfSalt}`; `kdfSalt` is the Argon2 salt the
//! transformed key belongs to and is authenticated as AES-GCM associated data.
//! The PRF output and the AES key never leave the JavaScript glue.

use js_sys::{Promise, Reflect, Uint8Array};
use keeweb_wasm::Key;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

#[wasm_bindgen(inline_js = r#"
const DB_NAME = "keeweb-rs-quick-unlock";
const STORE = "vaults";
const encoder = new TextEncoder();

function failure(kind, message) {
    const error = new Error(message);
    error.kind = kind;
    return error;
}

function webauthnFailure(error, action) {
    switch (error && error.name) {
        case "NotAllowedError":
        case "AbortError":
            return failure("cancelled", `${action} was cancelled or timed out.`);
        case "SecurityError":
            return failure("unsupported", "Fingerprint unlock needs HTTPS (or localhost) and a domain name, not an IP address.");
        case "NotSupportedError":
            return failure("unsupported", "This device has no fingerprint reader or other built-in authenticator.");
        case "InvalidStateError":
            return failure("failed", `${action} failed: the authenticator rejected the request.`);
        default:
            return failure("failed", `${action} failed.`);
    }
}

function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

async function deriveKey(prfOutput, vault) {
    const ikm = ArrayBuffer.isView(prfOutput)
        ? new Uint8Array(prfOutput.buffer, prfOutput.byteOffset, prfOutput.byteLength)
        : new Uint8Array(prfOutput);
    try {
        const material = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
        return await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: new Uint8Array(0),
                info: encoder.encode("keeweb-rs quick unlock v1\u0000" + vault),
            },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"],
        );
    } finally {
        ikm.fill(0);
    }
}

export async function quSupport() {
    if (typeof PublicKeyCredential === "undefined" || !window.isSecureContext || !navigator.credentials) {
        return "unavailable";
    }
    if (typeof PublicKeyCredential.getClientCapabilities === "function") {
        try {
            const capabilities = await PublicKeyCredential.getClientCapabilities();
            if (capabilities.userVerifyingPlatformAuthenticator === false) {
                return "unavailable";
            }
            if (capabilities["extension:prf"] === true) {
                return "available";
            }
            if (capabilities["extension:prf"] === false) {
                return "unavailable";
            }
        } catch (_) {
            // Fall through to the older platform authenticator check.
        }
    }
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        try {
            if (!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) {
                return "unavailable";
            }
        } catch (_) {
            return "unavailable";
        }
    }
    return "unknown";
}

export async function quEvaluate(credentialId, prfSalt, vault) {
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: {
                rpId: location.hostname,
                challenge: randomBytes(32),
                // Copies: the arguments may be views into WebAssembly memory.
                allowCredentials: [{ type: "public-key", id: credentialId.slice() }],
                userVerification: "required",
                timeout: 120000,
                extensions: { prf: { eval: { first: prfSalt.slice() } } },
            },
        });
    } catch (error) {
        throw webauthnFailure(error, "Fingerprint unlock");
    }
    const prf = assertion.getClientExtensionResults().prf;
    if (!prf || !prf.results || !prf.results.first) {
        throw failure("unsupported", "The authenticator did not return the WebAuthn PRF result that fingerprint unlock needs.");
    }
    return deriveKey(prf.results.first, vault);
}

// `create` comes first so it still runs within the user activation of the click.
export async function quEnroll(vault, label, userId) {
    const prfSalt = randomBytes(32);
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: {
                rp: { id: location.hostname, name: "KeeWeb RS" },
                user: { id: userId.slice(), name: label, displayName: label },
                challenge: randomBytes(32),
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },
                    { type: "public-key", alg: -257 },
                ],
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required",
                    residentKey: "preferred",
                },
                attestation: "none",
                timeout: 120000,
                extensions: { prf: { eval: { first: prfSalt } } },
            },
        });
    } catch (error) {
        throw webauthnFailure(error, "Fingerprint setup");
    }
    const credentialId = new Uint8Array(credential.rawId);
    const prf = credential.getClientExtensionResults().prf;
    if (!prf || prf.enabled !== true) {
        await quForgetCredential(credentialId);
        throw failure("unsupported", "This browser or authenticator does not support the WebAuthn PRF extension that fingerprint unlock needs.");
    }
    // Some authenticators only evaluate the PRF during an assertion.
    const key = prf.results && prf.results.first
        ? await deriveKey(prf.results.first, vault)
        : await quEvaluate(credentialId, prfSalt, vault);
    return { credentialId, prfSalt, key };
}

export async function quSeal(key, plaintext, kdfSalt) {
    const iv = randomBytes(12);
    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: kdfSalt }, key, plaintext),
    );
    return { iv, ciphertext };
}

export async function quOpen(key, iv, ciphertext, kdfSalt) {
    try {
        return new Uint8Array(
            await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: kdfSalt }, key, ciphertext),
        );
    } catch (_) {
        throw failure("invalid", "The stored fingerprint unlock data could not be decrypted.");
    }
}

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(failure("failed", "The browser's IndexedDB storage is unavailable."));
    });
}

async function withStore(mode, operation) {
    const database = await openDatabase();
    try {
        return await new Promise((resolve, reject) => {
            const transaction = database.transaction(STORE, mode);
            const request = operation(transaction.objectStore(STORE));
            transaction.oncomplete = () => resolve(request.result);
            transaction.onerror = () => reject(failure("failed", "The browser's IndexedDB storage failed."));
            transaction.onabort = () => reject(failure("failed", "The browser's IndexedDB storage failed."));
        });
    } finally {
        database.close();
    }
}

export function quLoad(vault) {
    return withStore("readonly", (store) => store.get(vault));
}

export function quStore(vault, record) {
    return withStore("readwrite", (store) => store.put(record, vault));
}

export function quDelete(vault) {
    return withStore("readwrite", (store) => store.delete(vault));
}

// Asks the platform to drop a passkey this page no longer uses, where supported.
export async function quForgetCredential(credentialId) {
    if (typeof PublicKeyCredential === "undefined" || typeof PublicKeyCredential.signalUnknownCredential !== "function") {
        return;
    }
    let binary = "";
    for (const byte of credentialId) {
        binary += String.fromCharCode(byte);
    }
    const encoded = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    try {
        await PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId: encoded });
    } catch (_) {
        // Best effort only.
    }
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = quSupport)]
    fn js_support() -> Promise;
    #[wasm_bindgen(js_name = quEvaluate)]
    fn js_evaluate(credential_id: &[u8], prf_salt: &[u8], vault: &str) -> Promise;
    #[wasm_bindgen(js_name = quEnroll)]
    fn js_enroll(vault: &str, label: &str, user_id: &[u8]) -> Promise;
    #[wasm_bindgen(js_name = quSeal)]
    fn js_seal(key: &JsValue, plaintext: &[u8], kdf_salt: &[u8]) -> Promise;
    #[wasm_bindgen(js_name = quOpen)]
    fn js_open(key: &JsValue, iv: &[u8], ciphertext: &[u8], kdf_salt: &[u8]) -> Promise;
    #[wasm_bindgen(js_name = quLoad)]
    fn js_load(vault: &str) -> Promise;
    #[wasm_bindgen(js_name = quStore)]
    fn js_store(vault: &str, record: &JsValue) -> Promise;
    #[wasm_bindgen(js_name = quDelete)]
    fn js_delete(vault: &str) -> Promise;
    #[wasm_bindgen(js_name = quForgetCredential)]
    fn js_forget_credential(credential_id: &[u8]) -> Promise;
}

/// What the browser reports about WebAuthn PRF on a platform authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    Available,
    /// The browser cannot tell before trying; enrollment reports the outcome.
    Unknown,
    Unavailable,
}

/// Why fingerprint unlock did not produce keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    /// The user dismissed the prompt, or it is unusable right now; the record stays.
    Declined(String),
    /// The stored record cannot be decrypted or parsed; it should be forgotten.
    Invalid(String),
}

/// Keys recovered from the stored record, plus the AES key that sealed them so the
/// record can be updated without another fingerprint prompt.
pub struct StoredKeys {
    pub composite: Key,
    pub transformed: Key,
    pub kdf_salt: Vec<u8>,
    sealer: Sealer,
}

impl StoredKeys {
    /// Replaces the stored keys after the vault was re-salted elsewhere.
    pub async fn restore(
        &self,
        vault: &str,
        transformed: &[u8; 32],
        kdf_salt: &[u8],
    ) -> Result<(), String> {
        self.sealer
            .store(vault, &self.composite, transformed, kdf_salt)
            .await
    }
}

struct Sealer {
    key: JsValue,
    credential_id: Vec<u8>,
    prf_salt: Vec<u8>,
}

impl Sealer {
    async fn store(
        &self,
        vault: &str,
        composite: &[u8; 32],
        transformed: &[u8; 32],
        kdf_salt: &[u8],
    ) -> Result<(), String> {
        let mut plaintext = Zeroizing::new([0u8; 64]);
        plaintext[..32].copy_from_slice(composite);
        plaintext[32..].copy_from_slice(transformed);
        let sealed = await_js(js_seal(&self.key, plaintext.as_slice(), kdf_salt))
            .await
            .map_err(|error| error.message)?;
        let record = js_sys::Object::new();
        let fields: [(&str, JsValue); 6] = [
            ("version", JsValue::from(1)),
            ("credentialId", bytes(&self.credential_id).into()),
            ("prfSalt", bytes(&self.prf_salt).into()),
            ("iv", get(&sealed, "iv")),
            ("ciphertext", get(&sealed, "ciphertext")),
            ("kdfSalt", bytes(kdf_salt).into()),
        ];
        for (name, value) in fields {
            Reflect::set(&record, &JsValue::from_str(name), &value)
                .map_err(|_| "Failed to prepare the fingerprint unlock record.".to_string())?;
        }
        await_js(js_store(vault, &record))
            .await
            .map(|_| ())
            .map_err(|error| error.message)
    }
}

struct JsFailure {
    kind: String,
    message: String,
}

async fn await_js(promise: Promise) -> Result<JsValue, JsFailure> {
    JsFuture::from(promise).await.map_err(|error| JsFailure {
        kind: get(&error, "kind").as_string().unwrap_or_default(),
        message: get(&error, "message")
            .as_string()
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "Fingerprint unlock failed.".to_string()),
    })
}

fn get(object: &JsValue, name: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(name)).unwrap_or(JsValue::UNDEFINED)
}

fn bytes(data: &[u8]) -> Uint8Array {
    Uint8Array::from(data)
}

fn byte_field(object: &JsValue, name: &str) -> Option<Vec<u8>> {
    get(object, name)
        .dyn_into::<Uint8Array>()
        .ok()
        .map(|array| array.to_vec())
}

pub async fn support() -> Support {
    match await_js(js_support())
        .await
        .ok()
        .and_then(|value| value.as_string())
    {
        Some(value) if value == "available" => Support::Available,
        Some(value) if value == "unknown" => Support::Unknown,
        _ => Support::Unavailable,
    }
}

/// The fingerprint unlock record stored for one vault on this device. It holds no
/// usable secret without the authenticator.
#[derive(Clone)]
pub struct Record(JsValue);

/// The record for `vault`, if fingerprint unlock is set up for it on this device.
pub async fn load(vault: &str) -> Option<Record> {
    await_js(js_load(vault))
        .await
        .ok()
        .filter(JsValue::is_object)
        .map(Record)
}

/// Creates a platform credential for `vault` and stores its keys under it. `label`
/// names the credential in the platform's passkey list.
pub async fn enroll(
    vault: &str,
    label: &str,
    composite: &[u8; 32],
    transformed: &[u8; 32],
    kdf_salt: &[u8],
) -> Result<(), String> {
    // A stable user handle per vault makes re-enrollment replace the vault's passkey
    // instead of adding another; hashing keeps the server path out of it.
    let user_id = Sha256::digest(format!("keeweb-rs vault\0{vault}"));
    let enrolled = await_js(js_enroll(vault, label, &user_id[..16]))
        .await
        .map_err(|error| error.message)?;
    let credential_id = byte_field(&enrolled, "credentialId").unwrap_or_default();
    let sealer = Sealer {
        key: get(&enrolled, "key"),
        prf_salt: byte_field(&enrolled, "prfSalt").unwrap_or_default(),
        credential_id,
    };
    let stored = sealer.store(vault, composite, transformed, kdf_salt).await;
    if stored.is_err() {
        let _ = await_js(js_forget_credential(&sealer.credential_id)).await;
    }
    stored
}

/// Asks for the fingerprint and decrypts the keys in `record`, which was loaded for
/// `vault` beforehand so the prompt follows the user's click without delay.
pub async fn unlock(vault: &str, record: &Record) -> Result<StoredKeys, UnlockError> {
    let invalid =
        || UnlockError::Invalid("The stored fingerprint unlock data is damaged.".to_string());
    let record = &record.0;
    let field = |name: &str| byte_field(record, name).ok_or_else(invalid);
    let credential_id = field("credentialId")?;
    let prf_salt = field("prfSalt")?;
    let iv = field("iv")?;
    let ciphertext = field("ciphertext")?;
    let kdf_salt = field("kdfSalt")?;

    let key = await_js(js_evaluate(&credential_id, &prf_salt, vault))
        .await
        .map_err(|error| UnlockError::Declined(error.message))?;
    let plaintext = await_js(js_open(&key, &iv, &ciphertext, &kdf_salt))
        .await
        .map_err(|error| match error.kind.as_str() {
            "invalid" => UnlockError::Invalid(error.message),
            _ => UnlockError::Declined(error.message),
        })?
        .dyn_into::<Uint8Array>()
        .map_err(|_| invalid())?;
    let mut keys = Zeroizing::new([0u8; 64]);
    let complete = plaintext.length() == 64;
    if complete {
        plaintext.copy_to(keys.as_mut_slice());
    }
    plaintext.fill(0, 0, plaintext.length());
    if !complete {
        return Err(invalid());
    }

    let mut composite = Zeroizing::new([0u8; 32]);
    let mut transformed = Zeroizing::new([0u8; 32]);
    composite.copy_from_slice(&keys[..32]);
    transformed.copy_from_slice(&keys[32..]);
    Ok(StoredKeys {
        composite,
        transformed,
        kdf_salt,
        sealer: Sealer {
            key,
            credential_id,
            prf_salt,
        },
    })
}

/// Deletes the record for `vault` and asks the platform to drop its credential.
pub async fn forget(vault: &str) -> Result<(), String> {
    let record = await_js(js_load(vault)).await.unwrap_or(JsValue::UNDEFINED);
    await_js(js_delete(vault))
        .await
        .map_err(|error| error.message)?;
    if let Some(credential_id) = byte_field(&record, "credentialId") {
        let _ = await_js(js_forget_credential(&credential_id)).await;
    }
    Ok(())
}
