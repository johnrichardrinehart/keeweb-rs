//! KDBX4 decryption with externally-derived key
//!
//! This module allows using an externally-computed KDF result (e.g., from a faster
//! JavaScript Argon2 SIMD implementation) instead of the internal rust-argon2.

use crate::error::{Error, Result};
use base64::Engine;
use byteorder::{ByteOrder, LittleEndian};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256, Sha512};
use hmac::{Hmac, Mac};
use aes::Aes256;
use cipher::BlockDecryptMut;
use flate2::read::GzDecoder;
use std::io::Read;

type HmacSha256 = Hmac<Sha256>;
type Aes256Cbc = cbc::Decryptor<Aes256>;

// KDBX4 header field types
const HEADER_END: u8 = 0;
const HEADER_CIPHER_ID: u8 = 2;
const HEADER_COMPRESSION_FLAGS: u8 = 3;
const HEADER_MASTER_SEED: u8 = 4;
const HEADER_ENCRYPTION_IV: u8 = 7;
const HEADER_KDF_PARAMETERS: u8 = 11;

// Inner header field types
const INNER_HEADER_END: u8 = 0;
const INNER_HEADER_STREAM_ID: u8 = 1;
const INNER_HEADER_STREAM_KEY: u8 = 2;

// KDF parameter keys (as UTF-8 strings in VariantDictionary)
const KDF_UUID_ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b,
    0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_UUID_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73,
    0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

/// KDF parameters extracted from KDBX4 header
#[derive(Debug, Clone)]
pub struct KdfParams {
    pub kdf_type: KdfType,
    pub salt: Vec<u8>,
    pub memory_kb: u64,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KdfType {
    Argon2d,
    Argon2id,
}

/// Parsed KDBX4 header information
#[derive(Debug)]
pub struct Kdbx4Header {
    pub kdf_params: KdfParams,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
    pub compression: bool,
    pub header_data: Vec<u8>,
    pub header_end_pos: usize,
}

/// Parse the KDBX4 outer header to extract KDF parameters
pub fn parse_kdbx4_header(data: &[u8]) -> Result<Kdbx4Header> {
    // Verify KDBX signature
    if data.len() < 12 {
        return Err(Error::ParseError("File too short".to_string()));
    }

    let sig1 = LittleEndian::read_u32(&data[0..4]);
    let sig2 = LittleEndian::read_u32(&data[4..8]);

    // KDBX signature: 0x9AA2D903 0xB54BFB67
    if sig1 != 0x9AA2D903 || sig2 != 0xB54BFB67 {
        return Err(Error::ParseError("Invalid KDBX signature".to_string()));
    }

    let version_minor = LittleEndian::read_u16(&data[8..10]);
    let version_major = LittleEndian::read_u16(&data[10..12]);

    if version_major != 4 {
        return Err(Error::ParseError(format!(
            "Unsupported KDBX version: {}.{}",
            version_major, version_minor
        )));
    }

    let mut pos = 12; // Start after version header
    let mut master_seed = None;
    let mut encryption_iv = None;
    let mut kdf_params = None;
    let mut compression = false;

    // Parse header fields
    loop {
        if pos + 5 > data.len() {
            return Err(Error::ParseError("Truncated header".to_string()));
        }

        let field_id = data[pos];
        let field_len = LittleEndian::read_u32(&data[pos + 1..pos + 5]) as usize;
        pos += 5;

        if pos + field_len > data.len() {
            return Err(Error::ParseError("Truncated header field".to_string()));
        }

        let field_data = &data[pos..pos + field_len];
        pos += field_len;

        match field_id {
            HEADER_END => break,
            HEADER_MASTER_SEED => master_seed = Some(field_data.to_vec()),
            HEADER_ENCRYPTION_IV => encryption_iv = Some(field_data.to_vec()),
            HEADER_COMPRESSION_FLAGS => {
                compression = LittleEndian::read_u32(field_data) == 1;
            }
            HEADER_KDF_PARAMETERS => {
                kdf_params = Some(parse_kdf_params(field_data)?);
            }
            HEADER_CIPHER_ID => {
                // We only support AES-256 for now
                // UUID: 31c1f2e6-bf71-4350-be58-05216afc5aff
            }
            _ => {} // Ignore unknown fields
        }
    }

    let header_data = data[0..pos].to_vec();

    Ok(Kdbx4Header {
        kdf_params: kdf_params.ok_or_else(|| Error::ParseError("Missing KDF parameters".to_string()))?,
        master_seed: master_seed.ok_or_else(|| Error::ParseError("Missing master seed".to_string()))?,
        encryption_iv: encryption_iv.ok_or_else(|| Error::ParseError("Missing encryption IV".to_string()))?,
        compression,
        header_data,
        header_end_pos: pos,
    })
}

/// Parse KDF parameters from VariantDictionary format
fn parse_kdf_params(data: &[u8]) -> Result<KdfParams> {
    // VariantDictionary format:
    // - u16 version (0x0100)
    // - entries until terminator
    // - entry: u8 type, u32 key_len, [key], u32 value_len, [value]

    if data.len() < 2 {
        return Err(Error::ParseError("KDF params too short".to_string()));
    }

    let mut pos = 2; // Skip version

    let mut uuid: Option<[u8; 16]> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut memory: Option<u64> = None;
    let mut iterations: Option<u64> = None;
    let mut parallelism: Option<u32> = None;
    let mut version: Option<u32> = None;

    while pos < data.len() {
        let entry_type = data[pos];
        pos += 1;

        if entry_type == 0 {
            break; // Terminator
        }

        if pos + 4 > data.len() {
            break;
        }
        let key_len = LittleEndian::read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + key_len > data.len() {
            break;
        }
        let key = std::str::from_utf8(&data[pos..pos + key_len]).unwrap_or("");
        pos += key_len;

        if pos + 4 > data.len() {
            break;
        }
        let value_len = LittleEndian::read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if pos + value_len > data.len() {
            break;
        }
        let value = &data[pos..pos + value_len];
        pos += value_len;

        match key {
            "$UUID" => {
                if value.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(value);
                    uuid = Some(arr);
                }
            }
            "S" => salt = Some(value.to_vec()), // Salt
            "M" => {
                if value.len() >= 8 {
                    memory = Some(LittleEndian::read_u64(value));
                }
            }
            "I" | "T" => {
                // Iterations (I for AES-KDF, T for Argon2)
                if value.len() >= 8 {
                    iterations = Some(LittleEndian::read_u64(value));
                }
            }
            "P" => {
                if value.len() >= 4 {
                    parallelism = Some(LittleEndian::read_u32(value));
                }
            }
            "V" => {
                if value.len() >= 4 {
                    version = Some(LittleEndian::read_u32(value));
                }
            }
            _ => {}
        }
    }

    let uuid = uuid.ok_or_else(|| Error::ParseError("Missing KDF UUID".to_string()))?;

    let kdf_type = if uuid == KDF_UUID_ARGON2D {
        KdfType::Argon2d
    } else if uuid == KDF_UUID_ARGON2ID {
        KdfType::Argon2id
    } else {
        return Err(Error::ParseError("Unsupported KDF type".to_string()));
    };

    Ok(KdfParams {
        kdf_type,
        salt: salt.ok_or_else(|| Error::ParseError("Missing KDF salt".to_string()))?,
        memory_kb: memory.ok_or_else(|| Error::ParseError("Missing KDF memory".to_string()))? / 1024,
        iterations: iterations.ok_or_else(|| Error::ParseError("Missing KDF iterations".to_string()))?,
        parallelism: parallelism.unwrap_or(1),
        version: version.unwrap_or(0x13),
    })
}

/// Decrypt KDBX4 database using a pre-computed transformed key
///
/// The `transformed_key` should be the 32-byte output of Argon2 KDF
pub fn decrypt_kdbx4_with_key(
    data: &[u8],
    password: &str,
    transformed_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let header = parse_kdbx4_header(data)?;

    // Compute composite key from password
    let password_hash = Sha256::digest(password.as_bytes());
    let composite_key = Sha256::digest(&password_hash);

    // Note: The transformed_key parameter replaces the slow KDF step
    // It should be computed as: Argon2(composite_key, salt, params)

    // Compute master key
    let mut master_key_input = Vec::with_capacity(header.master_seed.len() + 32);
    master_key_input.extend_from_slice(&header.master_seed);
    master_key_input.extend_from_slice(transformed_key);
    let master_key = Sha256::digest(&master_key_input);

    // Verify header HMAC
    let header_end = header.header_end_pos;
    let header_sha256_pos = header_end;
    let header_hmac_pos = header_end + 32;
    let payload_start = header_end + 64;

    if data.len() < payload_start {
        return Err(Error::ParseError("File truncated after header".to_string()));
    }

    // Verify header SHA256
    let stored_header_sha256 = &data[header_sha256_pos..header_sha256_pos + 32];
    let computed_header_sha256 = Sha256::digest(&header.header_data);
    if stored_header_sha256 != computed_header_sha256.as_slice() {
        return Err(Error::DecryptError("Header hash mismatch".to_string()));
    }

    // Compute HMAC key
    let mut hmac_key_input = Vec::new();
    hmac_key_input.extend_from_slice(&header.master_seed);
    hmac_key_input.extend_from_slice(transformed_key);
    hmac_key_input.extend_from_slice(&[0x01]); // HMAC_KEY_END
    let hmac_key = Sha512::digest(&hmac_key_input);

    // Verify header HMAC
    let stored_header_hmac = &data[header_hmac_pos..header_hmac_pos + 32];
    let block_key = compute_hmac_block_key(u64::MAX, &hmac_key)?;
    let mut mac = HmacSha256::new_from_slice(&block_key)
        .map_err(|_| Error::DecryptError("HMAC init failed".to_string()))?;
    mac.update(&header.header_data);
    let computed_header_hmac = mac.finalize().into_bytes();

    if stored_header_hmac != computed_header_hmac.as_slice() {
        return Err(Error::DecryptError("Invalid password or corrupted file".to_string()));
    }

    // Read HMAC block stream
    let encrypted_payload = read_hmac_block_stream(&data[payload_start..], &hmac_key)?;

    // Decrypt with AES-256-CBC
    let decrypted = decrypt_aes256_cbc(&encrypted_payload, &master_key, &header.encryption_iv)?;

    // Decompress if needed
    let xml_data = if header.compression {
        decompress_gzip(&decrypted)?
    } else {
        decrypted
    };

    Ok(xml_data)
}

fn compute_hmac_block_key(block_index: u64, hmac_key: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    hasher.update(&block_index.to_le_bytes());
    hasher.update(hmac_key);
    Ok(hasher.finalize().to_vec())
}

fn read_hmac_block_stream(data: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 0;
    let mut block_index: u64 = 0;

    loop {
        if pos + 4 > data.len() {
            return Err(Error::ParseError("Truncated HMAC block".to_string()));
        }

        // Read HMAC (32 bytes)
        let block_hmac = &data[pos..pos + 32];
        pos += 32;

        // Read block size (4 bytes)
        let block_size = LittleEndian::read_u32(&data[pos..pos + 4]) as usize;
        pos += 4;

        if block_size == 0 {
            break; // End of stream
        }

        if pos + block_size > data.len() {
            return Err(Error::ParseError("Truncated HMAC block data".to_string()));
        }

        let block_data = &data[pos..pos + block_size];
        pos += block_size;

        // Verify block HMAC
        let block_key = compute_hmac_block_key(block_index, hmac_key)?;
        let mut mac = HmacSha256::new_from_slice(&block_key)
            .map_err(|_| Error::DecryptError("HMAC init failed".to_string()))?;
        mac.update(&block_index.to_le_bytes());
        mac.update(&(block_size as u32).to_le_bytes());
        mac.update(block_data);
        let computed_hmac = mac.finalize().into_bytes();

        if block_hmac != computed_hmac.as_slice() {
            return Err(Error::DecryptError("Block HMAC verification failed".to_string()));
        }

        result.extend_from_slice(block_data);
        block_index += 1;
    }

    Ok(result)
}

fn decrypt_aes256_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use cipher::block_padding::Pkcs7;

    let cipher = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| Error::DecryptError("AES init failed".to_string()))?;

    let mut buffer = data.to_vec();
    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::DecryptError("AES decryption failed".to_string()))?;

    Ok(decrypted.to_vec())
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)
        .map_err(|e| Error::ParseError(format!("Decompression failed: {}", e)))?;
    Ok(result)
}

/// Get the composite key from a password (for Argon2 input)
pub fn compute_composite_key(password: &str) -> [u8; 32] {
    let password_hash = Sha256::digest(password.as_bytes());
    let composite_key = Sha256::digest(&password_hash);
    let mut result = [0u8; 32];
    result.copy_from_slice(&composite_key);
    result
}

/// Inner header parsed from decrypted payload
#[derive(Debug)]
pub struct InnerHeader {
    pub stream_key: Vec<u8>,
    pub stream_id: u32,
    pub xml_start: usize,
}

/// Parse the inner header from decrypted payload
fn parse_inner_header(data: &[u8]) -> Result<InnerHeader> {
    let mut pos = 0;
    let mut stream_key = None;
    let mut stream_id = None;

    loop {
        if pos + 5 > data.len() {
            return Err(Error::ParseError("Truncated inner header".to_string()));
        }

        let field_id = data[pos];
        let field_len = LittleEndian::read_u32(&data[pos + 1..pos + 5]) as usize;
        pos += 5;

        if pos + field_len > data.len() {
            return Err(Error::ParseError("Truncated inner header field".to_string()));
        }

        let field_data = &data[pos..pos + field_len];
        pos += field_len;

        match field_id {
            INNER_HEADER_END => break,
            INNER_HEADER_STREAM_ID => {
                if field_len >= 4 {
                    stream_id = Some(LittleEndian::read_u32(field_data));
                }
            }
            INNER_HEADER_STREAM_KEY => {
                stream_key = Some(field_data.to_vec());
            }
            _ => {} // Ignore unknown fields (like binary attachments)
        }
    }

    Ok(InnerHeader {
        stream_key: stream_key.ok_or_else(|| Error::ParseError("Missing inner stream key".to_string()))?,
        stream_id: stream_id.ok_or_else(|| Error::ParseError("Missing inner stream ID".to_string()))?,
        xml_start: pos,
    })
}

/// ChaCha20 cipher for decrypting protected values
pub struct ProtectedStreamCipher {
    cipher: ChaCha20,
}

impl ProtectedStreamCipher {
    /// Create a new cipher from the inner stream key
    pub fn new(stream_key: &[u8]) -> Result<Self> {
        // Hash the key with SHA-512
        let hash = Sha512::digest(stream_key);

        // First 32 bytes = key, next 12 bytes = nonce
        let key: [u8; 32] = hash[0..32].try_into()
            .map_err(|_| Error::DecryptError("Invalid key length".to_string()))?;
        let nonce: [u8; 12] = hash[32..44].try_into()
            .map_err(|_| Error::DecryptError("Invalid nonce length".to_string()))?;

        let cipher = ChaCha20::new(&key.into(), &nonce.into());

        Ok(Self { cipher })
    }

    /// Decrypt a base64-encoded protected value
    pub fn decrypt(&mut self, base64_value: &str) -> Result<String> {
        let encrypted = base64::engine::general_purpose::STANDARD.decode(base64_value)
            .map_err(|e| Error::DecryptError(format!("Base64 decode failed: {}", e)))?;

        let mut decrypted = encrypted;
        self.cipher.apply_keystream(&mut decrypted);

        String::from_utf8(decrypted)
            .map_err(|e| Error::DecryptError(format!("UTF-8 decode failed: {}", e)))
    }
}

/// Decrypt protected values in XML using ChaCha20
pub fn decrypt_protected_values(xml: &str, stream_key: &[u8]) -> Result<String> {
    let mut cipher = ProtectedStreamCipher::new(stream_key)?;
    let mut result = xml.to_string();
    let mut count = 0;

    // Find all Protected="True" values and decrypt them
    // KeePass uses Protected="True" (capital T)
    // Pattern: <Value Protected="True">base64data</Value>

    loop {
        // Find Protected="True" case-insensitively
        let lower = result.to_lowercase();
        let Some(protected_pos) = lower.find("protected=\"true\"") else {
            #[cfg(target_arch = "wasm32")]
            web_sys::console::log_1(&format!("Decrypted {} protected values", count).into());
            break;
        };
        count += 1;

        // Find the closing > after Protected="True"
        let Some(tag_end_rel) = result[protected_pos..].find('>') else {
            break;
        };
        let value_start = protected_pos + tag_end_rel + 1;

        let Some(relative_end) = result[value_start..].find("</Value>") else {
            break;
        };
        let value_end = value_start + relative_end;

        let base64_value = &result[value_start..value_end];

        // Decrypt the value
        let decrypted = cipher.decrypt(base64_value)?;

        // Replace in the result - also remove the Protected="True" attribute
        let tag_start = result[..protected_pos].rfind("<Value").unwrap_or(protected_pos);
        let replacement = format!("<Value>{}</Value>", decrypted);
        result.replace_range(tag_start..value_end + "</Value>".len(), &replacement);
    }

    Ok(result)
}

/// Decrypt KDBX4 database and return XML with decrypted protected values
pub fn decrypt_kdbx4_full(
    data: &[u8],
    password: &str,
    transformed_key: &[u8; 32],
) -> Result<String> {
    let header = parse_kdbx4_header(data)?;

    // Compute composite key from password
    let password_hash = Sha256::digest(password.as_bytes());
    let _composite_key = Sha256::digest(&password_hash);

    // Compute master key
    let mut master_key_input = Vec::with_capacity(header.master_seed.len() + 32);
    master_key_input.extend_from_slice(&header.master_seed);
    master_key_input.extend_from_slice(transformed_key);
    let master_key = Sha256::digest(&master_key_input);

    // Verify header HMAC
    let header_end = header.header_end_pos;
    let header_sha256_pos = header_end;
    let header_hmac_pos = header_end + 32;
    let payload_start = header_end + 64;

    if data.len() < payload_start {
        return Err(Error::ParseError("File truncated after header".to_string()));
    }

    // Verify header SHA256
    let stored_header_sha256 = &data[header_sha256_pos..header_sha256_pos + 32];
    let computed_header_sha256 = Sha256::digest(&header.header_data);
    if stored_header_sha256 != computed_header_sha256.as_slice() {
        return Err(Error::DecryptError("Header hash mismatch".to_string()));
    }

    // Compute HMAC key
    let mut hmac_key_input = Vec::new();
    hmac_key_input.extend_from_slice(&header.master_seed);
    hmac_key_input.extend_from_slice(transformed_key);
    hmac_key_input.extend_from_slice(&[0x01]); // HMAC_KEY_END
    let hmac_key = Sha512::digest(&hmac_key_input);

    // Verify header HMAC
    let stored_header_hmac = &data[header_hmac_pos..header_hmac_pos + 32];
    let block_key = compute_hmac_block_key(u64::MAX, &hmac_key)?;
    let mut mac = HmacSha256::new_from_slice(&block_key)
        .map_err(|_| Error::DecryptError("HMAC init failed".to_string()))?;
    mac.update(&header.header_data);
    let computed_header_hmac = mac.finalize().into_bytes();

    if stored_header_hmac != computed_header_hmac.as_slice() {
        return Err(Error::DecryptError("Invalid password or corrupted file".to_string()));
    }

    // Read HMAC block stream
    let encrypted_payload = read_hmac_block_stream(&data[payload_start..], &hmac_key)?;

    // Decrypt with AES-256-CBC
    let decrypted = decrypt_aes256_cbc(&encrypted_payload, &master_key, &header.encryption_iv)?;

    // Decompress if needed
    let payload_data = if header.compression {
        decompress_gzip(&decrypted)?
    } else {
        decrypted
    };

    // Parse inner header to get stream key
    let inner_header = parse_inner_header(&payload_data)?;

    // Extract XML
    let xml_bytes = &payload_data[inner_header.xml_start..];
    let xml = String::from_utf8(xml_bytes.to_vec())
        .map_err(|e| Error::ParseError(format!("XML decode failed: {}", e)))?;

    // Decrypt protected values using ChaCha20
    let decrypted_xml = decrypt_protected_values(&xml, &inner_header.stream_key)?;

    Ok(decrypted_xml)
}
