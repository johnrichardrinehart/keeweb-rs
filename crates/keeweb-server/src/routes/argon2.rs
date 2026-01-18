//! Argon2 hash computation endpoint
//!
//! This endpoint provides native-speed Argon2 key derivation for browsers
//! that cannot efficiently compute high-memory Argon2 in WebAssembly.

use argon2::{Algorithm, Argon2, Params, Version};
use axum::{extract::Json, http::StatusCode, response::IntoResponse};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

/// Request to compute Argon2 hash
#[derive(Debug, Deserialize)]
pub struct Argon2Request {
    /// Base64-encoded password bytes
    pub password: String,
    /// Base64-encoded salt
    pub salt: String,
    /// Memory cost in KiB
    pub memory_kib: u32,
    /// Time cost (iterations)
    pub iterations: u32,
    /// Parallelism (lanes)
    pub parallelism: u32,
    /// Output length in bytes
    pub output_len: usize,
    /// Argon2 variant: "d", "i", or "id" (default: "d")
    #[serde(default = "default_variant")]
    pub variant: String,
    /// Argon2 version: 16 (0x10) or 19 (0x13), default 19
    #[serde(default = "default_version")]
    pub version: u32,
}

fn default_variant() -> String {
    "d".to_string()
}

fn default_version() -> u32 {
    19 // 0x13
}

/// Response with computed hash
#[derive(Debug, Serialize)]
pub struct Argon2Response {
    /// Base64-encoded derived key
    pub hash: String,
    /// Time taken in milliseconds
    pub time_ms: u64,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct Argon2Error {
    pub error: String,
}

/// Compute Argon2 hash
///
/// POST /api/argon2
///
/// This endpoint runs Argon2 natively, which is much faster than WebAssembly
/// for high-memory configurations. The frontend can use this as an optional
/// "unlock helper" for databases with expensive KDF settings.
pub async fn compute_argon2(
    Json(req): Json<Argon2Request>,
) -> Result<impl IntoResponse, (StatusCode, Json<Argon2Error>)> {
    let start = std::time::Instant::now();

    // Decode inputs
    let password = BASE64
        .decode(&req.password)
        .map_err(|e| bad_request(format!("Invalid password encoding: {}", e)))?;

    let salt = BASE64
        .decode(&req.salt)
        .map_err(|e| bad_request(format!("Invalid salt encoding: {}", e)))?;

    // Parse algorithm variant
    let algorithm = match req.variant.to_lowercase().as_str() {
        "d" | "argon2d" => Algorithm::Argon2d,
        "i" | "argon2i" => Algorithm::Argon2i,
        "id" | "argon2id" => Algorithm::Argon2id,
        _ => return Err(bad_request(format!("Unknown variant: {}", req.variant))),
    };

    // Validate parameters
    if req.memory_kib < 8 {
        return Err(bad_request("Memory must be at least 8 KiB".to_string()));
    }
    if req.iterations < 1 {
        return Err(bad_request("Iterations must be at least 1".to_string()));
    }
    if req.parallelism < 1 {
        return Err(bad_request("Parallelism must be at least 1".to_string()));
    }
    if req.output_len < 4 || req.output_len > 1024 {
        return Err(bad_request(
            "Output length must be between 4 and 1024 bytes".to_string(),
        ));
    }

    // Log the request (without password)
    tracing::info!(
        "Argon2 request: variant={}, memory={}KiB ({}MB), iterations={}, parallelism={}, output_len={}, version={}",
        req.variant,
        req.memory_kib,
        req.memory_kib / 1024,
        req.iterations,
        req.parallelism,
        req.output_len,
        req.version
    );
    tracing::debug!("Password len={}, salt len={}", password.len(), salt.len());

    // Build Argon2 params
    let params = Params::new(
        req.memory_kib,
        req.iterations,
        req.parallelism,
        Some(req.output_len),
    )
    .map_err(|e| bad_request(format!("Invalid Argon2 parameters: {}", e)))?;

    let version = match req.version {
        16 => Version::V0x10,
        _ => Version::V0x13,
    };

    let argon2 = Argon2::new(algorithm, version, params);

    // Compute hash
    let mut output = vec![0u8; req.output_len];
    argon2
        .hash_password_into(&password, &salt, &mut output)
        .map_err(|e| {
            tracing::error!("Argon2 computation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Argon2Error {
                    error: format!("Argon2 computation failed: {}", e),
                }),
            )
        })?;

    let elapsed = start.elapsed();
    tracing::info!("Argon2 computation completed in {:?}", elapsed);
    tracing::debug!(
        "Hash first 16 bytes: {:02x?}",
        &output[..output.len().min(16)]
    );

    Ok(Json(Argon2Response {
        hash: BASE64.encode(&output),
        time_ms: elapsed.as_millis() as u64,
    }))
}

fn bad_request(message: String) -> (StatusCode, Json<Argon2Error>) {
    (
        StatusCode::BAD_REQUEST,
        Json(Argon2Error { error: message }),
    )
}
