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
use zeroize::Zeroizing;

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

pub(crate) fn compute_hmac_block_key(block_index: u64, hmac_key: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    hasher.update(block_index.to_le_bytes());
    hasher.update(hmac_key);
    Ok(hasher.finalize().to_vec())
}

pub(crate) fn read_hmac_block_stream(data: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut pos = 0;
    let mut block_index: u64 = 0;

    loop {
        if pos + 36 > data.len() {
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

pub(crate) fn decrypt_aes256_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    use cipher::block_padding::Pkcs7;

    let cipher = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| Error::DecryptError("AES init failed".to_string()))?;

    let mut buffer = data.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::DecryptError("AES decryption failed".to_string()))?;

    Ok(decrypted.to_vec())
}

pub(crate) fn decrypt_chacha20_poly1305(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
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

pub(crate) fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut result = Vec::new();
    decoder
        .read_to_end(&mut result)
        .map_err(|e| Error::ParseError(format!("Decompression failed: {}", e)))?;
    Ok(result)
}

/// Get the composite key from a password (for Argon2 input)
pub fn compute_composite_key(password: &str) -> [u8; 32] {
    composite_of(Some(password), None)
}

/// SHA-256(SHA-256(password) || key_file_key(key_file)); either part optional, at least one required.
pub fn compute_composite_key_with_key_file(
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<[u8; 32]> {
    if password.is_none() && key_file.is_none() {
        return Err(Error::InvalidKey(
            "A password or a key file is required".to_string(),
        ));
    }
    let key_file_key = key_file.map(key_file_key).transpose()?;
    Ok(composite_of(
        password,
        key_file_key.as_ref().map(|key| key.as_slice()),
    ))
}

fn composite_of(password: Option<&str>, key_file_key: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if let Some(password) = password {
        let password_hash = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(password.as_bytes())));
        hasher.update(password_hash.as_slice());
    }
    if let Some(key) = key_file_key {
        hasher.update(key);
    }
    hasher.finalize().into()
}

/// The 32-or-more-byte key-file component (KeePass KcpKeyFile semantics).
pub fn key_file_key(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let without_bom = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    if let Some(key) = xml_key_file_key(without_bom)? {
        return Ok(key);
    }
    if data.len() == 32 {
        return Ok(Zeroizing::new(data.to_vec()));
    }
    if data.len() == 64 {
        if let Some(key) = decode_hex(data) {
            return Ok(key);
        }
    }
    Ok(Zeroizing::new(Sha256::digest(data).to_vec()))
}

const KEY_FILE_VERSION: [&[u8]; 3] = [b"KeyFile", b"Meta", b"Version"];
const KEY_FILE_DATA: [&[u8]; 3] = [b"KeyFile", b"Key", b"Data"];

fn damaged_key_file(problem: &str) -> Error {
    Error::InvalidKey(format!("The key file is damaged: {problem}"))
}

/// Key data of a KeePass XML key file. `None` when `data` is not a well-formed XML
/// document with a `KeyFile` root; such files are key material as a whole.
fn xml_key_file_key(data: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(data);
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut saw_root = false;
    let mut version = String::new();
    let mut hash: Option<String> = None;
    let mut key_data: Option<Zeroizing<String>> = None;

    loop {
        let Ok(event) = reader.read_event() else {
            return Ok(None);
        };
        let empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                if path.is_empty() {
                    if saw_root || start.name().as_ref() != b"KeyFile" {
                        return Ok(None);
                    }
                    saw_root = true;
                }
                path.push(start.name().as_ref().to_vec());
                if path == KEY_FILE_DATA {
                    for attr in start.attributes() {
                        let Ok(attr) = attr else {
                            return Ok(None);
                        };
                        if attr.key.as_ref() == b"Hash" {
                            let Ok(value) = attr.decode_and_unescape_value(reader.decoder()) else {
                                return Ok(None);
                            };
                            hash = Some(value.into_owned());
                        }
                    }
                    key_data.get_or_insert_with(Default::default);
                }
                if empty {
                    path.pop();
                }
            }
            Event::End(_) => {
                path.pop();
            }
            Event::Text(text) => {
                let Ok(text) = text.decode() else {
                    return Ok(None);
                };
                if path.is_empty() {
                    if !text.trim().is_empty() {
                        return Ok(None);
                    }
                } else if path == KEY_FILE_VERSION {
                    version.push_str(&text);
                } else if path == KEY_FILE_DATA {
                    if let Some(key_data) = key_data.as_mut() {
                        key_data.push_str(&text);
                    }
                }
            }
            // Neither hex, base64 nor a version number needs escaping or CDATA.
            Event::GeneralRef(_) | Event::CData(_)
                if path == KEY_FILE_DATA || path == KEY_FILE_VERSION =>
            {
                return Err(damaged_key_file("it contains unexpected characters"));
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !saw_root || !path.is_empty() {
        return Ok(None);
    }

    let key_data = key_data.ok_or_else(|| damaged_key_file("it contains no key data"))?;
    let key = match version.trim() {
        "2.0" | "2.00" => {
            let digits: Zeroizing<Vec<u8>> = Zeroizing::new(
                key_data
                    .bytes()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect(),
            );
            let key = decode_hex(&digits)
                .ok_or_else(|| damaged_key_file("its key data is not hexadecimal"))?;
            if let Some(hash) = hash {
                let digest = Sha256::digest(key.as_slice());
                let matches = decode_hex(hash.trim().as_bytes())
                    .is_some_and(|expected| expected.as_slice() == &digest[..4]);
                if !matches {
                    return Err(damaged_key_file("its hash does not match"));
                }
            }
            key
        }
        "1.0" | "1.00" => Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(key_data.trim())
                .map_err(|_| damaged_key_file("its key data is not base64"))?,
        ),
        _ => {
            return Err(Error::InvalidKey(
                "The key file version is not supported".to_string(),
            ));
        }
    };
    if key.is_empty() {
        return Err(damaged_key_file("it contains no key data"));
    }
    Ok(Some(key))
}

fn decode_hex(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |byte: u8| char::from(byte).to_digit(16).map(|digit| digit as u8);
    let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() / 2));
    for pair in text.chunks_exact(2) {
        bytes.push(nibble(pair[0])? << 4 | nibble(pair[1])?);
    }
    Some(bytes)
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

    /// Encrypt a plaintext value and return it base64-encoded, advancing the stream
    pub fn encrypt(&mut self, plaintext: &str) -> String {
        let mut data = plaintext.as_bytes().to_vec();
        self.cipher.apply_keystream(&mut data);
        base64::engine::general_purpose::STANDARD.encode(data)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::KdbxDocument;
    use keepass::config::{DatabaseConfig, KdfConfig};
    use keepass::db::{Entry, Value};
    use keepass::{Database, DatabaseKey};

    const PASSWORD: &str = "correct horse battery staple";

    const KEY: [u8; 32] = [
        0x36, 0x05, 0x7B, 0x1C, 0x35, 0x03, 0x7F, 0xD9, 0x62, 0x25, 0x78, 0x93, 0xC0, 0xA2, 0x24,
        0x03, 0xEE, 0x3F, 0x8F, 0xBB, 0x50, 0x4D, 0x99, 0x81, 0x08, 0xB8, 0x21, 0xCB, 0x00, 0xD2,
        0x8F, 0x89,
    ];

    // Hash is the first 4 bytes of SHA-256(KEY), precomputed with sha256sum. The
    // fixtures avoid tabs and whitespace around base64 because the keepass crate, used
    // as the reference writer below, does not strip them.
    const XML_V2: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash="A65F0C2D">
            36057B1C 35037FD9 62257893 C0A22403
            EE3F8FBB 504D9981 08B821CB 00D28F89
        </Data>
    </Key>
</KeyFile>
"#;

    const XML_V1: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>1.00</Version>
    </Meta>
    <Key>
        <Data>NgV7HDUDf9liJXiTwKIkA+4/j7tQTZmBCLghywDSj4k=</Data>
    </Key>
</KeyFile>
"#;

    /// Test-only hex parser, independent of the code under test.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key_of(data: &[u8]) -> Vec<u8> {
        key_file_key(data).unwrap().to_vec()
    }

    #[test]
    fn xml_v2_key_file_yields_its_verified_data() {
        assert_eq!(key_of(XML_V2.as_bytes()), KEY);
        let lowercase_hash = XML_V2.replace("A65F0C2D", "a65f0c2d");
        assert_eq!(key_of(lowercase_hash.as_bytes()), KEY);
        let without_hash = XML_V2.replace(r#" Hash="A65F0C2D""#, "");
        assert_eq!(key_of(without_hash.as_bytes()), KEY);
        let tab_indented = XML_V2.replace("    ", "\t").replace('\n', "\r\n");
        assert_eq!(key_of(tab_indented.as_bytes()), KEY);
    }

    #[test]
    fn xml_v2_key_file_with_wrong_hash_is_rejected() {
        let wrong = XML_V2.replace("A65F0C2D", "A65F0C2E");
        let error = key_file_key(wrong.as_bytes()).unwrap_err().to_string();
        assert_eq!(error, "The key file is damaged: its hash does not match");

        let tampered = XML_V2.replace("00D28F89", "00D28F88");
        assert!(key_file_key(tampered.as_bytes()).is_err());
    }

    #[test]
    fn xml_key_file_with_bad_version_or_data_is_rejected() {
        let future = XML_V2.replace("<Version>2.0</Version>", "<Version>3.0</Version>");
        assert_eq!(
            key_file_key(future.as_bytes()).unwrap_err().to_string(),
            "The key file version is not supported"
        );
        let not_hex = XML_V2.replace("36057B1C", "36057B1G");
        assert!(key_file_key(not_hex.as_bytes()).is_err());
        let not_base64 = XML_V1.replace("NgV7", "Ng!7");
        assert!(key_file_key(not_base64.as_bytes()).is_err());
    }

    #[test]
    fn xml_v1_key_file_yields_base64_data() {
        assert_eq!(key_of(XML_V1.as_bytes()), KEY);
        let padded = XML_V1
            .replace("<Data>", "<Data>\n\t\t")
            .replace("</Data>", "\n\t</Data>");
        assert_eq!(key_of(padded.as_bytes()), KEY);
    }

    #[test]
    fn bom_prefixed_xml_key_file_is_recognized() {
        let with_bom = format!("\u{feff}{XML_V2}");
        assert_eq!(key_of(with_bom.as_bytes()), KEY);
    }

    #[test]
    fn binary_32_byte_key_file_is_used_raw() {
        assert_eq!(key_of(&KEY), KEY);
    }

    #[test]
    fn hex_64_char_key_file_is_decoded() {
        let upper = "36057B1C35037FD962257893C0A22403EE3F8FBB504D998108B821CB00D28F89";
        assert_eq!(key_of(upper.as_bytes()), KEY);
        assert_eq!(key_of(upper.to_lowercase().as_bytes()), KEY);
    }

    #[test]
    fn other_key_files_are_hashed_whole() {
        assert_eq!(
            key_of(b"arbitrary key file contents\n"),
            hex("7229fb6ee6f4d9f993514a9e5019812fde25be00ca67163f56325bd88b79a27f")
        );
        assert_eq!(
            key_of(b""),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        // 64 bytes that are not all hex digits, and XML that is not a key file.
        let not_hex = [b'g'; 64];
        assert_eq!(key_of(&not_hex), Sha256::digest(not_hex).to_vec());
        let other_xml = b"<Not><KeyFile/></Not>";
        assert_eq!(key_of(other_xml), Sha256::digest(other_xml).to_vec());
    }

    #[test]
    fn composite_key_combines_password_and_key_file() {
        let both = compute_composite_key_with_key_file(Some(PASSWORD), Some(XML_V2.as_bytes()));
        assert_eq!(
            both.unwrap().to_vec(),
            hex("6f3e6e6828cda57e4118884b8a6bb982b68a3afbcace3eeac8dc5909065587ad")
        );

        let key_file_only = compute_composite_key_with_key_file(None, Some(XML_V2.as_bytes()));
        assert_eq!(
            key_file_only.unwrap().to_vec(),
            hex("a65f0c2d028c10bac56822728026ab4fb6556d30f279b2cca53d7ded45dff658")
        );

        let password_only = compute_composite_key_with_key_file(Some(PASSWORD), None);
        assert_eq!(password_only.unwrap(), compute_composite_key(PASSWORD));

        assert!(compute_composite_key_with_key_file(None, None).is_err());
    }

    fn written_by_keepass(key: DatabaseKey) -> Vec<u8> {
        let mut config = DatabaseConfig::default();
        config.kdf_config = match config.kdf_config {
            KdfConfig::Argon2 { version, .. } | KdfConfig::Argon2id { version, .. } => {
                KdfConfig::Argon2 {
                    iterations: 1,
                    memory: 64 * 1024,
                    parallelism: 1,
                    version,
                }
            }
            other => other,
        };
        let mut db = Database::new(config);
        let mut entry = Entry::new();
        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected("Mail".to_string()));
        db.root.add_child(entry);
        let mut written = Vec::new();
        db.save(&mut written, key).unwrap();
        written
    }

    fn open(data: &[u8], password: Option<&str>, key_file: Option<&[u8]>) -> Result<Vec<String>> {
        let params = KdbxDocument::kdf_request(data)?;
        let composite = compute_composite_key_with_key_file(password, key_file)?;
        let algorithm = match params.kdf_type {
            KdfType::Argon2d => argon2::Algorithm::Argon2d,
            KdfType::Argon2id => argon2::Algorithm::Argon2id,
        };
        let argon_params = argon2::Params::new(
            params.memory_kb as u32,
            params.iterations as u32,
            params.parallelism,
            Some(32),
        )
        .unwrap();
        let mut transformed = [0u8; 32];
        argon2::Argon2::new(algorithm, argon2::Version::V0x13, argon_params)
            .hash_password_into(&composite, &params.salt, &mut transformed)
            .unwrap();
        let document = KdbxDocument::open(data, &composite, &transformed)?;
        Ok(document
            .entries()
            .iter()
            .map(|entry| entry.title().to_string())
            .collect())
    }

    #[test]
    fn opens_keepass_database_protected_by_password_and_key_file() {
        let key = DatabaseKey::new()
            .with_password(PASSWORD)
            .with_keyfile(&mut XML_V2.as_bytes())
            .unwrap();
        let data = written_by_keepass(key);

        let titles = open(&data, Some(PASSWORD), Some(XML_V2.as_bytes())).unwrap();
        assert_eq!(titles, ["Mail"]);
        assert!(open(&data, Some(PASSWORD), None).is_err());
        assert!(open(&data, None, Some(XML_V2.as_bytes())).is_err());
    }

    #[test]
    fn opens_keepass_database_protected_by_key_file_only() {
        let arbitrary: &[u8] = b"arbitrary key file contents\n";
        for key_file in [XML_V2.as_bytes(), XML_V1.as_bytes(), &KEY, arbitrary] {
            let key = DatabaseKey::new().with_keyfile(&mut &key_file[..]).unwrap();
            let data = written_by_keepass(key);

            let titles = open(&data, None, Some(key_file)).unwrap();
            assert_eq!(titles, ["Mail"]);
            assert!(open(&data, Some(PASSWORD), Some(key_file)).is_err());
        }
        let data = written_by_keepass(
            DatabaseKey::new()
                .with_keyfile(&mut XML_V2.as_bytes())
                .unwrap(),
        );
        assert!(open(&data, None, Some(arbitrary)).is_err());
    }
}
