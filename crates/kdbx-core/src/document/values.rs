//! Encoding of KeePass XML scalar values: UUIDs, timestamps, booleans and tags.

use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, NaiveDateTime, Utc};
use uuid::Uuid;

/// Seconds between 0001-01-01T00:00:00Z (the KDBX 4 time origin) and the Unix epoch.
const KDBX_EPOCH_OFFSET: i64 = 62_135_596_800;

pub(crate) fn parse_uuid(text: &str) -> Option<Uuid> {
    let bytes = STANDARD.decode(text.trim()).ok()?;
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    Some(Uuid::from_bytes(bytes))
}

pub(crate) fn format_uuid(uuid: Uuid) -> String {
    STANDARD.encode(uuid.as_bytes())
}

/// Parses both KDBX 4 (base64 seconds since year 1) and KDBX 3 (ISO 8601) timestamps.
pub(crate) fn parse_time(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(time) = DateTime::parse_from_rfc3339(text) {
        return Some(time.with_timezone(&Utc));
    }
    if let Ok(time) = NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S") {
        return Some(time.and_utc());
    }
    let bytes = STANDARD.decode(text).ok()?;
    let seconds = i64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    DateTime::from_timestamp(seconds.checked_sub(KDBX_EPOCH_OFFSET)?, 0)
}

pub(crate) fn format_time(time: DateTime<Utc>) -> String {
    STANDARD.encode((time.timestamp() + KDBX_EPOCH_OFFSET).to_le_bytes())
}

pub(crate) fn parse_bool(text: &str) -> Option<bool> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("true") {
        Some(true)
    } else if text.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn format_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

/// KeePass separates tags with `;`; KeePassXC and older KeePass builds also accept `,`.
pub(crate) fn parse_tags(text: &str) -> Vec<String> {
    text.split([';', ','])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn format_tags(tags: &[String]) -> String {
    tags.join(";")
}

/// Current time truncated to whole seconds, the resolution KDBX stores.
pub(crate) fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap_or_default()
}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| Error::SaveError(format!("random number generator failed: {e}")))?;
    Ok(bytes)
}
