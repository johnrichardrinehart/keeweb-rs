//! TOTP (Time-based One-Time Password) generation for frontend
//!
//! This is a standalone implementation that doesn't require the keeweb-wasm module.

/// TOTP configuration parsed from an otp attribute
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Base32-encoded secret key
    pub secret: String,
    /// Number of digits in the generated code (default: 6)
    #[allow(dead_code)]
    pub digits: u32,
    /// Time period in seconds (default: 30)
    pub period: u32,
    /// Hash algorithm (default: SHA1)
    pub algorithm: TotpAlgorithm,
    /// Issuer (optional, for display purposes)
    #[allow(dead_code)]
    pub issuer: Option<String>,
    /// Account/label (optional, for display purposes)
    #[allow(dead_code)]
    pub label: Option<String>,
}

/// Supported TOTP hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

/// TOTP generation result
pub struct TotpResult {
    pub code: String,
    pub period: u32,
    pub remaining: u32,
    #[allow(dead_code)]
    pub digits: u32,
}

impl TotpConfig {
    /// Parse TOTP configuration from an otp attribute value
    pub fn parse(otp_value: &str) -> Result<Self, String> {
        let trimmed = otp_value.trim();

        if trimmed.starts_with("otpauth://") {
            Self::parse_otpauth_uri(trimmed)
        } else {
            Self::from_secret(trimmed)
        }
    }

    /// Create a config from a bare base32 secret with default parameters
    pub fn from_secret(secret: &str) -> Result<Self, String> {
        let clean = secret.trim().to_uppercase().replace(' ', "");
        if clean.is_empty() {
            return Err("TOTP secret is empty".to_string());
        }

        // Basic validation - base32 uses A-Z and 2-7
        for c in clean.chars() {
            if !matches!(c, 'A'..='Z' | '2'..='7' | '=') {
                return Err("Invalid base32 encoding".to_string());
            }
        }

        Ok(Self {
            secret: clean,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            label: None,
        })
    }

    /// Parse an otpauth:// URI
    fn parse_otpauth_uri(uri: &str) -> Result<Self, String> {
        if !uri.starts_with("otpauth://totp/") {
            if uri.starts_with("otpauth://hotp/") {
                return Err("HOTP (counter-based OTP) is not supported".to_string());
            }
            return Err("Invalid otpauth URI format".to_string());
        }

        let rest = &uri[15..]; // Skip "otpauth://totp/"

        let (label_part, query_part) = match rest.find('?') {
            Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
            None => (rest, None),
        };

        let label = url_decode(label_part);
        let (issuer_from_label, account) = if let Some(colon_pos) = label.find(':') {
            (
                Some(label[..colon_pos].to_string()),
                label[colon_pos + 1..].to_string(),
            )
        } else {
            (None, label)
        };

        let mut secret: Option<String> = None;
        let mut digits: u32 = 6;
        let mut period: u32 = 30;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut issuer: Option<String> = None;

        if let Some(query) = query_part {
            for param in query.split('&') {
                let (key, value) = match param.find('=') {
                    Some(pos) => (&param[..pos], url_decode(&param[pos + 1..])),
                    None => continue,
                };

                match key.to_lowercase().as_str() {
                    "secret" => secret = Some(value.to_uppercase().replace(' ', "")),
                    "digits" => digits = value.parse().unwrap_or(6),
                    "period" => period = value.parse().unwrap_or(30),
                    "algorithm" => {
                        algorithm = match value.to_uppercase().as_str() {
                            "SHA1" => TotpAlgorithm::Sha1,
                            "SHA256" => TotpAlgorithm::Sha256,
                            "SHA512" => TotpAlgorithm::Sha512,
                            _ => TotpAlgorithm::Sha1,
                        };
                    }
                    "issuer" => issuer = Some(value),
                    _ => {}
                }
            }
        }

        let secret = secret.ok_or("Missing secret parameter in URI")?;
        if secret.is_empty() {
            return Err("TOTP secret is empty".to_string());
        }

        let final_issuer = issuer.or(issuer_from_label);

        Ok(Self {
            secret,
            digits,
            period,
            algorithm,
            issuer: final_issuer,
            label: if account.is_empty() {
                None
            } else {
                Some(account)
            },
        })
    }

    /// Generate a TOTP code for the current time
    pub fn generate(&self) -> Result<TotpResult, String> {
        let timestamp = current_timestamp();
        self.generate_at(timestamp)
    }

    /// Generate a TOTP code for a specific Unix timestamp
    pub fn generate_at(&self, timestamp: u64) -> Result<TotpResult, String> {
        let secret_bytes = decode_base32(&self.secret)?;
        let counter = timestamp / self.period as u64;

        let code = match self.algorithm {
            TotpAlgorithm::Sha1 => hotp_sha1(&secret_bytes, counter, self.digits)?,
            TotpAlgorithm::Sha256 => hotp_sha256(&secret_bytes, counter, self.digits)?,
            TotpAlgorithm::Sha512 => hotp_sha512(&secret_bytes, counter, self.digits)?,
        };

        let remaining = self.period - (timestamp % self.period as u64) as u32;

        Ok(TotpResult {
            code,
            period: self.period,
            remaining,
            digits: self.digits,
        })
    }
}

/// Get current Unix timestamp using JavaScript Date
fn current_timestamp() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Decode a base32 string to bytes
fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim().to_uppercase();
    let input = input.trim_end_matches('=');

    if input.is_empty() {
        return Err("Empty secret".to_string());
    }

    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut result = Vec::new();

    for c in input.bytes() {
        let value = alphabet
            .iter()
            .position(|&x| x == c)
            .ok_or("Invalid base32 character")? as u64;

        bits = (bits << 5) | value;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            result.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(result)
}

/// Simple URL decoding
fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

// HMAC-SHA1 implementation using Web Crypto API would be complex,
// so we'll use a simple pure-Rust implementation

/// Generate HOTP code using SHA1
fn hotp_sha1(secret: &[u8], counter: u64, digits: u32) -> Result<String, String> {
    let hmac = hmac_sha1(secret, &counter.to_be_bytes());
    truncate_and_format(&hmac, digits)
}

/// Generate HOTP code using SHA256
fn hotp_sha256(secret: &[u8], counter: u64, digits: u32) -> Result<String, String> {
    let hmac = hmac_sha256(secret, &counter.to_be_bytes());
    truncate_and_format(&hmac, digits)
}

/// Generate HOTP code using SHA512
fn hotp_sha512(secret: &[u8], counter: u64, digits: u32) -> Result<String, String> {
    let hmac = hmac_sha512(secret, &counter.to_be_bytes());
    truncate_and_format(&hmac, digits)
}

/// Dynamic truncation and formatting (RFC 4226)
fn truncate_and_format(result: &[u8], digits: u32) -> Result<String, String> {
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulo = 10u32.pow(digits);
    let code = code % modulo;

    Ok(format!("{:0width$}", code, width = digits as usize))
}

// Simple HMAC implementations (pure Rust, no external crates needed in WASM)

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 20;

    let key = if key.len() > BLOCK_SIZE {
        sha1(key)
    } else {
        key.to_vec()
    };

    let mut key_block = [0u8; BLOCK_SIZE];
    key_block[..key.len()].copy_from_slice(&key);

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    const HASH_SIZE: usize = 32;

    let key = if key.len() > BLOCK_SIZE {
        sha256(key)
    } else {
        key.to_vec()
    };

    let mut key_block = [0u8; BLOCK_SIZE];
    key_block[..key.len()].copy_from_slice(&key);

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 128;
    const HASH_SIZE: usize = 64;

    let key = if key.len() > BLOCK_SIZE {
        sha512(key)
    } else {
        key.to_vec()
    };

    let mut key_block = [0u8; BLOCK_SIZE];
    key_block[..key.len()].copy_from_slice(&key);

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha512(&inner);

    let mut outer = Vec::with_capacity(BLOCK_SIZE + HASH_SIZE);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha512(&outer)
}

// Pure Rust SHA implementations

#[allow(clippy::needless_range_loop)]
fn sha1(data: &[u8]) -> Vec<u8> {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let ml = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&ml.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = Vec::with_capacity(20);
    result.extend_from_slice(&h0.to_be_bytes());
    result.extend_from_slice(&h1.to_be_bytes());
    result.extend_from_slice(&h2.to_be_bytes());
    result.extend_from_slice(&h3.to_be_bytes());
    result.extend_from_slice(&h4.to_be_bytes());
    result
}

fn sha256(data: &[u8]) -> Vec<u8> {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let ml = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&ml.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = Vec::with_capacity(32);
    for &word in &h {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}

fn sha512(data: &[u8]) -> Vec<u8> {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let ml = (data.len() as u128) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&ml.to_be_bytes());

    for chunk in padded.chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                chunk[i * 8],
                chunk[i * 8 + 1],
                chunk[i * 8 + 2],
                chunk[i * 8 + 3],
                chunk[i * 8 + 4],
                chunk[i * 8 + 5],
                chunk[i * 8 + 6],
                chunk[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = Vec::with_capacity(64);
    for &word in &h {
        result.extend_from_slice(&word.to_be_bytes());
    }
    result
}
