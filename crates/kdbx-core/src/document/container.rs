//! KDBX 4 container: outer header, HMAC block stream, outer cipher, compression and
//! inner header.

use super::values::random_bytes;
use crate::error::{Error, Result};
use crate::kdbx4_decrypt::{
    compute_hmac_block_key, decompress_gzip, decrypt_aes256_cbc, decrypt_chacha20_poly1305,
    read_hmac_block_stream,
};
use aes::Aes256;
use byteorder::{ByteOrder, LittleEndian};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use cipher::BlockEncryptMut;
use cipher::block_padding::Pkcs7;
use flate2::Compression;
use flate2::write::GzEncoder;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use std::io::Write;

type HmacSha256 = Hmac<Sha256>;

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2: u32 = 0xB54B_FB67;
const MAJOR_VERSION: u16 = 4;

const FIELD_END: u8 = 0;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_ENCRYPTION_IV: u8 = 7;

const INNER_END: u8 = 0;
const INNER_STREAM_ID: u8 = 1;
const INNER_STREAM_KEY: u8 = 2;
const INNER_BINARY: u8 = 3;

/// Inner random stream algorithm id for ChaCha20, the only one KDBX 4 writers use.
pub(crate) const STREAM_CHACHA20: u32 = 3;

/// KeePass writes the payload in 1 MiB HMAC blocks.
const HMAC_BLOCK_SIZE: usize = 1 << 20;

pub(crate) const CIPHER_AES256: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
pub(crate) const CIPHER_CHACHA20: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OuterCipher {
    Aes256Cbc,
    ChaCha20,
}

impl OuterCipher {
    fn iv_len(self) -> usize {
        match self {
            OuterCipher::Aes256Cbc => 16,
            OuterCipher::ChaCha20 => 12,
        }
    }
}

/// Outer header fields in file order. Master seed and encryption IV are replaced on
/// save; every other field (cipher, compression, KDF parameters including the salt,
/// public custom data, unknown fields) is written back unchanged.
#[derive(Clone, Debug)]
pub(crate) struct OuterHeader {
    pub minor: u16,
    pub fields: Vec<(u8, Vec<u8>)>,
    pub end: Vec<u8>,
    pub cipher: OuterCipher,
    pub compressed: bool,
}

impl OuterHeader {
    /// Parses the outer header; returns it with the offset of the header hash.
    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 12 {
            return Err(Error::ParseError("File too short".to_string()));
        }
        if LittleEndian::read_u32(&data[0..4]) != SIGNATURE_1
            || LittleEndian::read_u32(&data[4..8]) != SIGNATURE_2
        {
            return Err(Error::ParseError("Not a KDBX file".to_string()));
        }
        let minor = LittleEndian::read_u16(&data[8..10]);
        let major = LittleEndian::read_u16(&data[10..12]);
        if major != MAJOR_VERSION {
            return Err(Error::UnsupportedFormat(format!(
                "KDBX {major}.{minor} cannot be edited; only KDBX 4.x is supported \
                 (upgrade the database format in KeePass or KeePassXC)"
            )));
        }

        let mut pos = 12;
        let mut fields = Vec::new();
        let end = loop {
            if pos + 5 > data.len() {
                return Err(Error::ParseError("Truncated header".to_string()));
            }
            let id = data[pos];
            let len = LittleEndian::read_u32(&data[pos + 1..pos + 5]) as usize;
            pos += 5;
            if pos + len > data.len() {
                return Err(Error::ParseError("Truncated header field".to_string()));
            }
            let value = data[pos..pos + len].to_vec();
            pos += len;
            if id == FIELD_END {
                break value;
            }
            fields.push((id, value));
        };

        let field = |id: u8| fields.iter().find(|(i, _)| *i == id).map(|(_, v)| v);
        let cipher = match field(FIELD_CIPHER_ID).map(Vec::as_slice) {
            Some(id) if id == CIPHER_AES256 => OuterCipher::Aes256Cbc,
            Some(id) if id == CIPHER_CHACHA20 => OuterCipher::ChaCha20,
            Some(_) => {
                return Err(Error::UnsupportedFormat(
                    "Unsupported outer cipher; only AES-256 and ChaCha20 are supported".to_string(),
                ));
            }
            None => return Err(Error::ParseError("Missing cipher id".to_string())),
        };
        let compressed = match field(FIELD_COMPRESSION) {
            Some(v) if v.len() == 4 && LittleEndian::read_u32(v) == 0 => false,
            Some(v) if v.len() == 4 && LittleEndian::read_u32(v) == 1 => true,
            _ => {
                return Err(Error::ParseError(
                    "Missing or unsupported compression flag".to_string(),
                ));
            }
        };
        if field(FIELD_MASTER_SEED).is_none_or(|v| v.len() != 32) {
            return Err(Error::ParseError(
                "Missing or invalid master seed".to_string(),
            ));
        }
        if field(FIELD_ENCRYPTION_IV).is_none_or(|v| v.len() != cipher.iv_len()) {
            return Err(Error::ParseError(
                "Missing or invalid encryption IV".to_string(),
            ));
        }

        Ok((
            Self {
                minor,
                fields,
                end,
                cipher,
                compressed,
            },
            pos,
        ))
    }

    fn field(&self, id: u8) -> &[u8] {
        self.fields
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, v)| v.as_slice())
            .unwrap_or_default()
    }

    fn to_bytes(&self, master_seed: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE_1.to_le_bytes());
        out.extend_from_slice(&SIGNATURE_2.to_le_bytes());
        out.extend_from_slice(&self.minor.to_le_bytes());
        out.extend_from_slice(&MAJOR_VERSION.to_le_bytes());
        let mut push = |id: u8, value: &[u8]| {
            out.push(id);
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        };
        for (id, value) in &self.fields {
            match *id {
                FIELD_MASTER_SEED => push(*id, master_seed),
                FIELD_ENCRYPTION_IV => push(*id, iv),
                _ => push(*id, value),
            }
        }
        push(FIELD_END, &self.end);
        out
    }
}

/// An inner header binary (attachment content). Bit 0 of `flags` is KeePass's
/// "protect in memory" hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binary {
    pub flags: u8,
    pub data: Vec<u8>,
}

pub(crate) struct Decrypted {
    pub header: OuterHeader,
    pub stream_id: u32,
    pub stream_key: Vec<u8>,
    pub binaries: Vec<Binary>,
    pub xml: Vec<u8>,
}

/// Returns (cipher key, HMAC base key) as defined by KDBX 4.
fn derive_keys(master_seed: &[u8], transformed_key: &[u8; 32]) -> ([u8; 32], Vec<u8>) {
    let mut cipher_key = Sha256::new();
    cipher_key.update(master_seed);
    cipher_key.update(transformed_key);
    let mut hmac_key = Sha512::new();
    hmac_key.update(master_seed);
    hmac_key.update(transformed_key);
    hmac_key.update([0x01]);
    (cipher_key.finalize().into(), hmac_key.finalize().to_vec())
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| Error::DecryptError("HMAC init failed".to_string()))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn decrypt(data: &[u8], transformed_key: &[u8; 32]) -> Result<Decrypted> {
    let (header, header_end) = OuterHeader::parse(data)?;
    if data.len() < header_end + 64 {
        return Err(Error::ParseError("File truncated after header".to_string()));
    }
    let header_bytes = &data[..header_end];
    if Sha256::digest(header_bytes).as_slice() != &data[header_end..header_end + 32] {
        return Err(Error::ParseError(
            "Header hash mismatch: the file is corrupted".to_string(),
        ));
    }

    let (cipher_key, hmac_key) = derive_keys(header.field(FIELD_MASTER_SEED), transformed_key);
    let header_mac = hmac(
        &compute_hmac_block_key(u64::MAX, &hmac_key)?,
        &[header_bytes],
    )?;
    if header_mac.as_slice() != &data[header_end + 32..header_end + 64] {
        return Err(Error::InvalidCredentials);
    }

    let encrypted = read_hmac_block_stream(&data[header_end + 64..], &hmac_key)?;
    let iv = header.field(FIELD_ENCRYPTION_IV);
    let decrypted = match header.cipher {
        OuterCipher::Aes256Cbc => decrypt_aes256_cbc(&encrypted, &cipher_key, iv)?,
        OuterCipher::ChaCha20 => decrypt_chacha20_poly1305(&encrypted, &cipher_key, iv)?,
    };
    let payload = if header.compressed {
        decompress_gzip(&decrypted)?
    } else {
        decrypted
    };

    let mut pos = 0;
    let mut stream_id = None;
    let mut stream_key = None;
    let mut binaries = Vec::new();
    loop {
        if pos + 5 > payload.len() {
            return Err(Error::ParseError("Truncated inner header".to_string()));
        }
        let id = payload[pos];
        let len = LittleEndian::read_u32(&payload[pos + 1..pos + 5]) as usize;
        pos += 5;
        if pos + len > payload.len() {
            return Err(Error::ParseError(
                "Truncated inner header field".to_string(),
            ));
        }
        let value = &payload[pos..pos + len];
        pos += len;
        match id {
            INNER_END => break,
            INNER_STREAM_ID if len == 4 => stream_id = Some(LittleEndian::read_u32(value)),
            INNER_STREAM_KEY => stream_key = Some(value.to_vec()),
            INNER_BINARY if len >= 1 => binaries.push(Binary {
                flags: value[0],
                data: value[1..].to_vec(),
            }),
            _ => {
                return Err(Error::ParseError(format!(
                    "Invalid inner header field {id}"
                )));
            }
        }
    }

    Ok(Decrypted {
        header,
        stream_id: stream_id
            .ok_or_else(|| Error::ParseError("Missing inner stream id".to_string()))?,
        stream_key: stream_key
            .ok_or_else(|| Error::ParseError("Missing inner stream key".to_string()))?,
        binaries,
        xml: payload[pos..].to_vec(),
    })
}

/// Writes a KDBX 4 file with a fresh master seed and encryption IV.
pub(crate) fn encrypt(
    header: &OuterHeader,
    transformed_key: &[u8; 32],
    stream_key: &[u8],
    binaries: &[Binary],
    xml: &[u8],
) -> Result<Vec<u8>> {
    let master_seed = random_bytes(32)?;
    let iv = random_bytes(header.cipher.iv_len())?;
    let header_bytes = header.to_bytes(&master_seed, &iv);
    let (cipher_key, hmac_key) = derive_keys(&master_seed, transformed_key);

    let mut payload = Vec::with_capacity(
        xml.len()
            + stream_key.len()
            + binaries.iter().map(|b| b.data.len() + 6).sum::<usize>()
            + 20,
    );
    let mut push = |id: u8, parts: &[&[u8]]| {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        payload.push(id);
        payload.extend_from_slice(&(len as u32).to_le_bytes());
        for part in parts {
            payload.extend_from_slice(part);
        }
    };
    push(INNER_STREAM_ID, &[&STREAM_CHACHA20.to_le_bytes()]);
    push(INNER_STREAM_KEY, &[stream_key]);
    for binary in binaries {
        push(INNER_BINARY, &[&[binary.flags], &binary.data]);
    }
    push(INNER_END, &[]);
    payload.extend_from_slice(xml);

    let plain = if header.compressed {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&payload)
            .map_err(|e| Error::SaveError(format!("compression failed: {e}")))?;
        encoder
            .finish()
            .map_err(|e| Error::SaveError(format!("compression failed: {e}")))?
    } else {
        payload
    };

    let encrypted = match header.cipher {
        OuterCipher::Aes256Cbc => {
            let len = plain.len();
            let mut buffer = plain;
            buffer.resize(len + 16, 0);
            let encryptor = cbc::Encryptor::<Aes256>::new_from_slices(&cipher_key, &iv)
                .map_err(|_| Error::SaveError("AES init failed".to_string()))?;
            let written = encryptor
                .encrypt_padded_mut::<Pkcs7>(&mut buffer, len)
                .map_err(|_| Error::SaveError("AES encryption failed".to_string()))?
                .len();
            buffer.truncate(written);
            buffer
        }
        OuterCipher::ChaCha20 => {
            let nonce: [u8; 12] = iv
                .as_slice()
                .try_into()
                .map_err(|_| Error::SaveError("Invalid ChaCha20 nonce".to_string()))?;
            let mut buffer = plain;
            ChaCha20::new(&cipher_key.into(), &nonce.into()).apply_keystream(&mut buffer);
            buffer
        }
    };

    let mut out = Vec::with_capacity(header_bytes.len() + 64 + encrypted.len() + 64);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&Sha256::digest(&header_bytes));
    out.extend_from_slice(&hmac(
        &compute_hmac_block_key(u64::MAX, &hmac_key)?,
        &[&header_bytes],
    )?);

    // The stream always ends with an empty block.
    let chunks = encrypted
        .chunks(HMAC_BLOCK_SIZE)
        .chain(std::iter::once(&[][..]));
    for (index, chunk) in (0u64..).zip(chunks) {
        let size = (chunk.len() as u32).to_le_bytes();
        let mac = hmac(
            &compute_hmac_block_key(index, &hmac_key)?,
            &[&index.to_le_bytes(), &size, chunk],
        )?;
        out.extend_from_slice(&mac);
        out.extend_from_slice(&size);
        out.extend_from_slice(chunk);
    }
    Ok(out)
}
