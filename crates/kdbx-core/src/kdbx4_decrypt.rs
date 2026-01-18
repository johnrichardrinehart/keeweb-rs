//! KDBX4 decryption with externally-derived key
//!
//! This module allows using an externally-computed KDF result (e.g., from a faster
//! JavaScript Argon2 SIMD implementation) instead of the internal rust-argon2.

use crate::error::{Error, Result};
use aes::Aes256;
use base64::Engine;
use byteorder::{ByteOrder, LittleEndian};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use cipher::BlockDecryptMut;
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
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
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const KDF_UUID_ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

// Cipher UUIDs
const CIPHER_AES256_CBC: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const CIPHER_CHACHA20_POLY1305: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherType {
    Aes256Cbc,
    ChaCha20Poly1305,
}

/// Parsed KDBX4 header information
#[derive(Debug)]
pub struct Kdbx4Header {
    pub kdf_params: KdfParams,
    pub master_seed: Vec<u8>,
    pub encryption_iv: Vec<u8>,
    pub compression: bool,
    pub cipher_type: CipherType,
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
    let mut cipher_type = CipherType::Aes256Cbc; // Default

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
                if field_data.len() >= 16 {
                    if field_data[..16] == CIPHER_CHACHA20_POLY1305 {
                        cipher_type = CipherType::ChaCha20Poly1305;
                    } else if field_data[..16] == CIPHER_AES256_CBC {
                        cipher_type = CipherType::Aes256Cbc;
                    }
                    // Unknown cipher will use default (AES-256-CBC)
                }
            }
            _ => {} // Ignore unknown fields
        }
    }

    let header_data = data[0..pos].to_vec();

    Ok(Kdbx4Header {
        kdf_params: kdf_params
            .ok_or_else(|| Error::ParseError("Missing KDF parameters".to_string()))?,
        master_seed: master_seed
            .ok_or_else(|| Error::ParseError("Missing master seed".to_string()))?,
        encryption_iv: encryption_iv
            .ok_or_else(|| Error::ParseError("Missing encryption IV".to_string()))?,
        compression,
        cipher_type,
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
        memory_kb: memory.ok_or_else(|| Error::ParseError("Missing KDF memory".to_string()))?
            / 1024,
        iterations: iterations
            .ok_or_else(|| Error::ParseError("Missing KDF iterations".to_string()))?,
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

    // Compute composite key from password (unused here but kept for reference)
    let password_hash = Sha256::digest(password.as_bytes());
    let _composite_key = Sha256::digest(password_hash);

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
        return Err(Error::DecryptError(
            "Invalid password or corrupted file".to_string(),
        ));
    }

    // Read HMAC block stream
    let encrypted_payload = read_hmac_block_stream(&data[payload_start..], &hmac_key)?;

    // Decrypt based on cipher type
    let decrypted = match header.cipher_type {
        CipherType::Aes256Cbc => {
            decrypt_aes256_cbc(&encrypted_payload, &master_key, &header.encryption_iv)?
        }
        CipherType::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(&encrypted_payload, &master_key, &header.encryption_iv)?
        }
    };

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
    hasher.update(block_index.to_le_bytes());
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
            return Err(Error::DecryptError(
                "Block HMAC verification failed".to_string(),
            ));
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
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::DecryptError("AES decryption failed".to_string()))?;

    Ok(decrypted.to_vec())
}

fn decrypt_chacha20_poly1305(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    // KDBX4 uses ChaCha20 stream cipher (not the full AEAD mode)
    // The HMAC block stream already provides integrity verification
    // So we just need to apply the ChaCha20 keystream to decrypt
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    if key.len() != 32 {
        return Err(Error::DecryptError(
            "ChaCha20 requires 32-byte key".to_string(),
        ));
    }
    if nonce.len() != 12 {
        return Err(Error::DecryptError(
            "ChaCha20 requires 12-byte nonce".to_string(),
        ));
    }

    // ChaCha20 uses 32-byte key and 12-byte nonce
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| Error::DecryptError("Invalid key length".to_string()))?;
    let nonce_arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::DecryptError("Invalid nonce length".to_string()))?;

    let mut cipher = ChaCha20::new(&key_arr.into(), &nonce_arr.into());

    let mut buffer = data.to_vec();
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| Error::ParseError(format!("Decompression failed: {}", e)))?;
    Ok(result)
}

/// Get the composite key from a password (for Argon2 input)
pub fn compute_composite_key(password: &str) -> [u8; 32] {
    let password_hash = Sha256::digest(password.as_bytes());
    let composite_key = Sha256::digest(password_hash);
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
            return Err(Error::ParseError(
                "Truncated inner header field".to_string(),
            ));
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
        stream_key: stream_key
            .ok_or_else(|| Error::ParseError("Missing inner stream key".to_string()))?,
        stream_id: stream_id
            .ok_or_else(|| Error::ParseError("Missing inner stream ID".to_string()))?,
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
        let key: [u8; 32] = hash[0..32]
            .try_into()
            .map_err(|_| Error::DecryptError("Invalid key length".to_string()))?;
        let nonce: [u8; 12] = hash[32..44]
            .try_into()
            .map_err(|_| Error::DecryptError("Invalid nonce length".to_string()))?;

        let cipher = ChaCha20::new(&key.into(), &nonce.into());

        Ok(Self { cipher })
    }

    /// Decrypt a base64-encoded protected value
    pub fn decrypt(&mut self, base64_value: &str) -> Result<String> {
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(base64_value)
            .map_err(|e| Error::DecryptError(format!("Base64 decode failed: {}", e)))?;

        let mut decrypted = encrypted;
        self.cipher.apply_keystream(&mut decrypted);

        String::from_utf8(decrypted)
            .map_err(|e| Error::DecryptError(format!("UTF-8 decode failed: {}", e)))
    }
}

/// Decrypt protected values in XML using ChaCha20 with proper XML parsing
pub fn decrypt_protected_values(xml: &str, stream_key: &[u8]) -> Result<String> {
    use quick_xml::events::{BytesStart, BytesText, Event};
    use quick_xml::{Reader, Writer};
    use std::io::Cursor;

    let mut cipher = ProtectedStreamCipher::new(stream_key)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false); // Preserve whitespace in text content

    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut in_protected_value = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = e.name();
                if name.as_ref() == b"Value" {
                    // Check for Protected="True" or ProtectInMemory="True" attribute
                    let is_protected = e.attributes().any(|attr| {
                        if let Ok(attr) = attr {
                            (attr.key.as_ref() == b"Protected"
                                || attr.key.as_ref() == b"ProtectInMemory")
                                && (attr.value.as_ref() == b"True"
                                    || attr.value.as_ref() == b"true")
                        } else {
                            false
                        }
                    });

                    if is_protected {
                        in_protected_value = true;
                        // Write the tag WITH ProtectInMemory="True" so the parser knows it was protected
                        let mut new_elem = BytesStart::new("Value");
                        new_elem.push_attribute(("ProtectInMemory", "True"));
                        writer
                            .write_event(Event::Start(new_elem))
                            .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
                        continue;
                    }
                }
                writer
                    .write_event(Event::Start(e.clone()))
                    .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
            }
            Ok(Event::Text(ref e)) => {
                if in_protected_value {
                    // Get the raw text content
                    let raw_text = std::str::from_utf8(e.as_ref())
                        .map_err(|e| Error::ParseError(format!("UTF-8 error: {}", e)))?;
                    let base64_text = raw_text.trim();

                    if base64_text.is_empty() {
                        // Empty protected value, just write empty text
                        writer
                            .write_event(Event::Text(BytesText::new("")))
                            .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
                    } else {
                        // Decrypt the value
                        let decrypted = cipher.decrypt(base64_text)?;
                        // Escape the decrypted value for XML
                        writer
                            .write_event(Event::Text(BytesText::new(&decrypted)))
                            .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
                    }
                } else {
                    writer
                        .write_event(Event::Text(e.clone()))
                        .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
                }
            }
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"Value" && in_protected_value {
                    in_protected_value = false;
                }
                writer
                    .write_event(Event::End(e.clone()))
                    .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
            }
            Ok(Event::Empty(ref e)) => {
                // Self-closing tag like <Value Protected="True"/>
                let name = e.name();
                if name.as_ref() == b"Value" {
                    let is_protected = e.attributes().any(|attr| {
                        if let Ok(attr) = attr {
                            (attr.key.as_ref() == b"Protected"
                                || attr.key.as_ref() == b"ProtectInMemory")
                                && (attr.value.as_ref() == b"True"
                                    || attr.value.as_ref() == b"true")
                        } else {
                            false
                        }
                    });

                    if is_protected {
                        // Write as <Value ProtectInMemory="True"/> to preserve protection status
                        let mut new_elem = BytesStart::new("Value");
                        new_elem.push_attribute(("ProtectInMemory", "True"));
                        writer
                            .write_event(Event::Empty(new_elem))
                            .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
                        continue;
                    }
                }
                writer
                    .write_event(Event::Empty(e.clone()))
                    .map_err(|e| Error::ParseError(format!("XML write error: {}", e)))?;
            }
            Ok(Event::Eof) => break,
            Ok(e) => {
                // Pass through all other events (comments, CData, etc.)
                writer
                    .write_event(e)
                    .map_err(|err| Error::ParseError(format!("XML write error: {}", err)))?;
            }
            Err(e) => {
                return Err(Error::ParseError(format!(
                    "XML parse error at position {}: {}",
                    reader.error_position(),
                    e
                )));
            }
        }
    }

    let result = writer.into_inner().into_inner();
    String::from_utf8(result)
        .map_err(|e| Error::ParseError(format!("UTF-8 conversion failed: {}", e)))
}

/// Decrypt KDBX4 database with password only (runs Argon2 internally)
///
/// This function handles the complete decryption pipeline:
/// 1. Parses the KDBX4 header to extract KDF parameters
/// 2. Runs Argon2 KDF internally to derive the transformed key
/// 3. Decrypts the database payload
/// 4. Preserves ProtectInMemory attributes in the output XML
///
/// This is slower than `decrypt_kdbx4_full` with a pre-computed key, but provides
/// a unified code path that ensures protected attributes are always correctly handled.
pub fn decrypt_kdbx4_full_with_password(data: &[u8], password: &str) -> Result<String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let header = parse_kdbx4_header(data)?;

    // Compute composite key from password
    let composite_key = compute_composite_key(password);

    // Run Argon2 KDF to get transformed key
    let algorithm = match header.kdf_params.kdf_type {
        KdfType::Argon2d => Algorithm::Argon2d,
        KdfType::Argon2id => Algorithm::Argon2id,
    };

    let version = match header.kdf_params.version {
        0x10 => Version::V0x10,
        _ => Version::V0x13, // Default to latest version
    };

    let params = Params::new(
        header.kdf_params.memory_kb as u32,
        header.kdf_params.iterations as u32,
        header.kdf_params.parallelism,
        Some(32), // Output length
    )
    .map_err(|e| Error::DecryptError(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(algorithm, version, params);

    let mut transformed_key = [0u8; 32];
    argon2
        .hash_password_into(
            &composite_key,
            &header.kdf_params.salt,
            &mut transformed_key,
        )
        .map_err(|e| Error::DecryptError(format!("Argon2 error: {}", e)))?;

    // Now use the existing function with the derived key
    decrypt_kdbx4_full(data, password, &transformed_key)
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
    let _composite_key = Sha256::digest(password_hash);

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
        return Err(Error::DecryptError(
            "Invalid password or corrupted file".to_string(),
        ));
    }

    // Read HMAC block stream
    let encrypted_payload = read_hmac_block_stream(&data[payload_start..], &hmac_key)?;

    // Decrypt based on cipher type
    let decrypted = match header.cipher_type {
        CipherType::Aes256Cbc => {
            decrypt_aes256_cbc(&encrypted_payload, &master_key, &header.encryption_iv)?
        }
        CipherType::ChaCha20Poly1305 => {
            decrypt_chacha20_poly1305(&encrypted_payload, &master_key, &header.encryption_iv)?
        }
    };

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
