//! TOTP (Time-based One-Time Password) generation
//!
//! Implements RFC 6238 TOTP generation compatible with KeePassXC's otp attribute format.
//!
//! Supported formats:
//! - otpauth://totp/... URI format (KeePassXC standard)
//! - Bare base32 secret (uses default parameters: SHA1, 6 digits, 30 second period)

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// TOTP configuration parsed from an otp attribute
#[derive(Debug, Clone, PartialEq)]
pub struct TotpConfig {
    /// Base32-encoded secret key
    pub secret: String,
    /// Number of digits in the generated code (default: 6)
    pub digits: u32,
    /// Time period in seconds (default: 30)
    pub period: u32,
    /// Hash algorithm (default: SHA1)
    pub algorithm: TotpAlgorithm,
    /// Issuer (optional, for display purposes)
    pub issuer: Option<String>,
    /// Account/label (optional, for display purposes)
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

impl TotpConfig {
    /// Parse TOTP configuration from an otp attribute value
    ///
    /// Supports:
    /// - `otpauth://totp/...` URI format
    /// - Bare base32 secret (uses defaults: SHA1, 6 digits, 30s period)
    pub fn parse(otp_value: &str) -> Result<Self, TotpError> {
        let trimmed = otp_value.trim();

        if trimmed.starts_with("otpauth://") {
            Self::parse_otpauth_uri(trimmed)
        } else {
            // Assume it's a bare base32 secret
            Self::from_secret(trimmed)
        }
    }

    /// Create a config from a bare base32 secret with default parameters
    pub fn from_secret(secret: &str) -> Result<Self, TotpError> {
        // Validate it looks like base32
        let clean = secret.trim().to_uppercase().replace(' ', "");
        if clean.is_empty() {
            return Err(TotpError::EmptySecret);
        }

        // Basic validation - base32 uses A-Z and 2-7
        for c in clean.chars() {
            if !matches!(c, 'A'..='Z' | '2'..='7' | '=') {
                return Err(TotpError::InvalidBase32);
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
    fn parse_otpauth_uri(uri: &str) -> Result<Self, TotpError> {
        // Format: otpauth://totp/[label]?secret=[SECRET]&period=[PERIOD]&digits=[DIGITS]&issuer=[ISSUER]&algorithm=[ALGO]

        if !uri.starts_with("otpauth://totp/") {
            // We only support TOTP, not HOTP
            if uri.starts_with("otpauth://hotp/") {
                return Err(TotpError::HotpNotSupported);
            }
            return Err(TotpError::InvalidUri);
        }

        let rest = &uri[15..]; // Skip "otpauth://totp/"

        // Split into label and query parts
        let (label_part, query_part) = match rest.find('?') {
            Some(pos) => (&rest[..pos], Some(&rest[pos + 1..])),
            None => (rest, None),
        };

        // URL decode the label
        let label = url_decode(label_part);

        // Parse issuer from label (format: "Issuer:Account" or just "Account")
        let (issuer_from_label, account) = if let Some(colon_pos) = label.find(':') {
            (
                Some(label[..colon_pos].to_string()),
                label[colon_pos + 1..].to_string(),
            )
        } else {
            (None, label)
        };

        // Parse query parameters
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

        let secret = secret.ok_or(TotpError::MissingSecret)?;
        if secret.is_empty() {
            return Err(TotpError::EmptySecret);
        }

        // Use issuer from query param if present, otherwise from label
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
    pub fn generate(&self) -> Result<String, TotpError> {
        self.generate_at(current_timestamp())
    }

    /// Generate a TOTP code for a specific Unix timestamp
    pub fn generate_at(&self, timestamp: u64) -> Result<String, TotpError> {
        let secret_bytes = decode_base32(&self.secret)?;
        let counter = timestamp / self.period as u64;

        let code = match self.algorithm {
            TotpAlgorithm::Sha1 => hotp_sha1(&secret_bytes, counter, self.digits)?,
            TotpAlgorithm::Sha256 => hotp_sha256(&secret_bytes, counter, self.digits)?,
            TotpAlgorithm::Sha512 => hotp_sha512(&secret_bytes, counter, self.digits)?,
        };

        Ok(code)
    }

    /// Get the number of seconds remaining in the current period
    pub fn time_remaining(&self) -> u32 {
        let now = current_timestamp();
        self.period - (now % self.period as u64) as u32
    }
}

/// TOTP-related errors
#[derive(Debug, Clone, PartialEq)]
pub enum TotpError {
    /// The secret is empty
    EmptySecret,
    /// The secret is not valid base32
    InvalidBase32,
    /// The URI format is invalid
    InvalidUri,
    /// The secret parameter is missing from the URI
    MissingSecret,
    /// HOTP (counter-based) is not supported
    HotpNotSupported,
    /// HMAC computation failed
    HmacError,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpError::EmptySecret => write!(f, "TOTP secret is empty"),
            TotpError::InvalidBase32 => write!(f, "Invalid base32 encoding in secret"),
            TotpError::InvalidUri => write!(f, "Invalid otpauth URI format"),
            TotpError::MissingSecret => write!(f, "Missing secret parameter in URI"),
            TotpError::HotpNotSupported => write!(f, "HOTP (counter-based OTP) is not supported"),
            TotpError::HmacError => write!(f, "HMAC computation failed"),
        }
    }
}

impl std::error::Error for TotpError {}

/// Generate HOTP code using SHA1
fn hotp_sha1(secret: &[u8], counter: u64, digits: u32) -> Result<String, TotpError> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| TotpError::HmacError)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    truncate_and_format(&result, digits)
}

/// Generate HOTP code using SHA256
fn hotp_sha256(secret: &[u8], counter: u64, digits: u32) -> Result<String, TotpError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TotpError::HmacError)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    truncate_and_format(&result, digits)
}

/// Generate HOTP code using SHA512
fn hotp_sha512(secret: &[u8], counter: u64, digits: u32) -> Result<String, TotpError> {
    let mut mac = HmacSha512::new_from_slice(secret).map_err(|_| TotpError::HmacError)?;
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    truncate_and_format(&result, digits)
}

/// Dynamic truncation and formatting (RFC 4226)
fn truncate_and_format(result: &[u8], digits: u32) -> Result<String, TotpError> {
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    // Modulo to get desired number of digits
    let modulo = 10u32.pow(digits);
    let code = code % modulo;

    // Zero-pad to the specified number of digits
    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Decode a base32 string to bytes
fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
    let input = input.trim().to_uppercase();
    let input = input.trim_end_matches('='); // Remove padding

    if input.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut bits: u64 = 0;
    let mut bit_count = 0;
    let mut result = Vec::new();

    for c in input.bytes() {
        let value = alphabet
            .iter()
            .position(|&x| x == c)
            .ok_or(TotpError::InvalidBase32)? as u64;

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

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bare_secret() {
        let config = TotpConfig::parse("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(config.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
    }

    #[test]
    fn test_parse_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let config = TotpConfig::parse(uri).unwrap();
        assert_eq!(config.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(config.issuer, Some("Example".to_string()));
        assert_eq!(config.label, Some("alice@google.com".to_string()));
    }

    #[test]
    fn test_parse_otpauth_with_algorithm() {
        let uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60";
        let config = TotpConfig::parse(uri).unwrap();
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 60);
    }

    #[test]
    fn test_generate_totp() {
        // Test vector from RFC 6238
        // Secret: "12345678901234567890" (ASCII)
        // Time: 59 (counter = 1)
        // Expected: 94287082 (SHA1, 8 digits, 30s period) per RFC 6238
        // For 6 digits: 287082 (last 6 digits via modulo)

        let config = TotpConfig {
            // "12345678901234567890" in base32 is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            digits: 8,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            label: None,
        };

        // At time 59, counter = 59/30 = 1
        let code = config.generate_at(59).unwrap();
        assert_eq!(code, "94287082");

        // Test 6 digits version
        let config6 = TotpConfig {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            label: None,
        };
        let code6 = config6.generate_at(59).unwrap();
        assert_eq!(code6, "287082");
    }

    #[test]
    fn test_decode_base32() {
        // "Hello!" in base32 is "JBSWY3DPEE======"
        let decoded = decode_base32("JBSWY3DPEE").unwrap();
        assert_eq!(decoded, b"Hello!");
    }

    #[test]
    fn test_empty_secret() {
        assert_eq!(TotpConfig::parse(""), Err(TotpError::EmptySecret));
    }

    #[test]
    fn test_hotp_not_supported() {
        let uri = "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=0";
        assert_eq!(TotpConfig::parse(uri), Err(TotpError::HotpNotSupported));
    }
}
