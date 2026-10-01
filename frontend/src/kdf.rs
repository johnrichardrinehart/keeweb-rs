//! Derivation of the 32-byte transformed key of a KDBX 4 file.
//!
//! Every unlock and every merge with a server revision goes through
//! [`derive_transformed_key`], which picks the fastest available Argon2: the native
//! helper, the parallel argon2-pthread worker, or the single-threaded fallback in the
//! key worker.

use crate::argon2_client::Argon2Client;
use crate::helper_client;
use crate::worker_client::WorkerClient;
use futures::channel::oneshot;
use keeweb_wasm::{Key, WasmKdfParams};
use std::cell::RefCell;
use zeroize::Zeroizing;

// WASM is single-threaded, so the clients live in thread-locals.
thread_local! {
    static WORKER_CLIENT: RefCell<Option<WorkerClient>> = const { RefCell::new(None) };
    static ARGON2_CLIENT: RefCell<Option<Argon2Client>> = const { RefCell::new(None) };
    static ARGON2_READY: RefCell<bool> = const { RefCell::new(false) };
}

/// Without the helper, files needing this much Argon2 memory skip the parallel
/// WebAssembly build, which cannot allocate it.
const PARALLEL_MEMORY_LIMIT_MB: u64 = 256;

/// Initialize the argon2-pthread worker (call once at startup).
pub fn init_argon2<F>(callback: F)
where
    F: FnOnce(Result<(), String>) + 'static,
{
    let created = ARGON2_CLIENT.with(|client| {
        let mut client = client.borrow_mut();
        if client.is_none() {
            *client = Some(
                Argon2Client::new()
                    .map_err(|e| format!("Failed to create argon2 client: {:?}", e))?,
            );
        }
        Ok::<(), String>(())
    });
    if let Err(error) = created {
        callback(Err(error));
        return;
    }

    ARGON2_CLIENT.with(|client| {
        if let Some(ac) = &*client.borrow() {
            ac.init(move |result| {
                if result.is_ok() {
                    ARGON2_READY.with(|ready| *ready.borrow_mut() = true);
                }
                callback(result);
            });
        }
    });
}

fn is_argon2_ready() -> bool {
    ARGON2_READY.with(|ready| *ready.borrow())
}

fn into_key(bytes: Vec<u8>) -> Result<Key, String> {
    let bytes = Zeroizing::new(bytes);
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("Key derivation returned {} bytes", bytes.len()))?;
    Ok(Zeroizing::new(array))
}

async fn parallel_argon2(params: &WasmKdfParams, composite_key: &[u8; 32]) -> Result<Key, String> {
    let (sender, receiver) = oneshot::channel();
    ARGON2_CLIENT.with(|client| match &*client.borrow() {
        Some(ac) => ac.hash(
            &params.kdf_type(),
            composite_key.to_vec(),
            params.salt(),
            params.iterations() as u32,
            params.memory_kb() as u32,
            params.parallelism(),
            32,
            move |result| {
                let _ = sender.send(result);
            },
        ),
        None => {
            let _ = sender.send(Err("Argon2 client not initialized".to_string()));
        }
    });
    receiver
        .await
        .map_err(|_| "Argon2 worker stopped".to_string())?
        .and_then(into_key)
}

async fn worker_argon2(
    params: &WasmKdfParams,
    composite_key: &[u8; 32],
    fast: bool,
) -> Result<Key, String> {
    let (sender, receiver) = oneshot::channel();
    WORKER_CLIENT.with(|client| {
        let mut client = client.borrow_mut();
        if client.is_none() {
            match WorkerClient::new() {
                Ok(worker) => *client = Some(worker),
                Err(e) => {
                    let _ = sender.send(Err(format!("Failed to create worker: {:?}", e)));
                    return;
                }
            }
        }
        if let Some(worker) = &*client {
            worker.derive_key(params, composite_key, fast, move |result| {
                let _ = sender.send(result);
            });
        }
    });
    receiver
        .await
        .map_err(|_| "Key worker stopped".to_string())?
        .and_then(into_key)
}

/// Run Argon2 with `params` over `composite_key`.
pub async fn derive_transformed_key(
    params: &WasmKdfParams,
    composite_key: &[u8; 32],
) -> Result<Key, String> {
    let memory_mb = params.memory_kb() / 1024;

    // Native Argon2 is several times faster than WebAssembly at every memory size.
    if helper_client::is_helper_configured() {
        match helper_client::check_helper_available().await {
            Ok(true) => {
                match helper_client::helper_argon2_hash(
                    &params.kdf_type(),
                    composite_key,
                    &params.salt(),
                    params.iterations() as u32,
                    params.memory_kb() as u32,
                    params.parallelism(),
                    32,
                    params.version(),
                )
                .await
                {
                    Ok((key, _server_time_ms)) => return into_key(key),
                    Err(e) => log::warn!("Helper Argon2 failed ({e}); using the slow fallback"),
                }
            }
            Ok(false) => log::info!("Helper unavailable; using the slow fallback"),
            Err(e) => log::warn!("Helper check failed ({e}); using the slow fallback"),
        }
        return worker_argon2(params, composite_key, false).await;
    }

    if memory_mb >= PARALLEL_MEMORY_LIMIT_MB {
        return worker_argon2(params, composite_key, false).await;
    }

    if is_argon2_ready() {
        match parallel_argon2(params, composite_key).await {
            Ok(key) => return Ok(key),
            Err(e) => log::warn!("Parallel Argon2 failed ({e}); retrying in the key worker"),
        }
    }
    worker_argon2(params, composite_key, true).await
}
