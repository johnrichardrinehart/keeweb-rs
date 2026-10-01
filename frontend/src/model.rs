//! Helpers over the document view types shared by the components.

use chrono::{DateTime, Utc};
use keeweb_wasm::document::{EntryView, GroupView};
use uuid::Uuid;
use wasm_bindgen::JsValue;

pub const TITLE: &str = "Title";
pub const USER_NAME: &str = "UserName";
pub const PASSWORD: &str = "Password";
pub const URL: &str = "URL";
pub const NOTES: &str = "Notes";

/// The five strings every KeePass entry has, in KeePass order.
pub const STANDARD_FIELDS: [&str; 5] = [TITLE, USER_NAME, PASSWORD, URL, NOTES];

/// Keys that different KeePass clients use for the TOTP configuration, by priority.
const OTP_FIELDS: [&str; 5] = ["otp", "OTP", "TOTP Seed", "TOTP", "totp"];

/// Highest standard KeePass icon id; icons/database/{0..=68}.svg are vendored.
pub const MAX_STANDARD_ICON: u32 = 68;

pub fn is_standard_field(key: &str) -> bool {
    STANDARD_FIELDS.contains(&key)
}

pub fn is_otp_field(key: &str) -> bool {
    OTP_FIELDS.contains(&key)
}

pub fn field<'a>(entry: &'a EntryView, key: &str) -> &'a str {
    entry.field(key).unwrap_or_default()
}

/// Title for lists and dialogs; never empty.
pub fn display_title(entry: &EntryView) -> String {
    let title = entry.title().trim();
    if title.is_empty() {
        "(untitled)".to_string()
    } else {
        title.to_string()
    }
}

pub fn otp_value(entry: &EntryView) -> Option<&str> {
    OTP_FIELDS
        .iter()
        .filter_map(|key| entry.field(key))
        .find(|value| !value.trim().is_empty())
}

pub fn group_display_name(group: &GroupView) -> String {
    if group.name.trim().is_empty() {
        "(unnamed group)".to_string()
    } else {
        group.name.clone()
    }
}

/// `group` and every group below it.
pub fn subtree(groups: &[GroupView], group: Uuid) -> Vec<Uuid> {
    let mut found = vec![group];
    let mut index = 0;
    while index < found.len() {
        let parent = found[index];
        found.extend(
            groups
                .iter()
                .filter(|candidate| candidate.parent == Some(parent))
                .map(|candidate| candidate.uuid),
        );
        index += 1;
    }
    found
}

/// "Root / Parent / Group"
pub fn group_path(groups: &[GroupView], group: Uuid) -> String {
    let mut names = Vec::new();
    let mut current = Some(group);
    while let Some(uuid) = current {
        let Some(view) = groups.iter().find(|candidate| candidate.uuid == uuid) else {
            break;
        };
        names.push(group_display_name(view));
        current = view.parent;
        if names.len() > groups.len() {
            break;
        }
    }
    names.reverse();
    names.join(" / ")
}

pub fn now_millis() -> f64 {
    js_sys::Date::now()
}

pub fn is_expired(time: Option<DateTime<Utc>>) -> bool {
    time.is_some_and(|time| (time.timestamp_millis() as f64) < now_millis())
}

fn js_date(time: DateTime<Utc>) -> js_sys::Date {
    js_sys::Date::new(&JsValue::from_f64(time.timestamp_millis() as f64))
}

/// Date and time in the browser's locale and time zone.
pub fn format_local(time: DateTime<Utc>) -> String {
    js_date(time)
        .to_locale_string("default", &JsValue::UNDEFINED)
        .into()
}

/// Value for `<input type="datetime-local">` in the browser's time zone.
pub fn to_datetime_local(time: DateTime<Utc>) -> String {
    let date = js_date(time);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}",
        date.get_full_year(),
        date.get_month() + 1,
        date.get_date(),
        date.get_hours(),
        date.get_minutes()
    )
}

/// Parses an `<input type="datetime-local">` value as local time.
pub fn from_datetime_local(value: &str) -> Option<DateTime<Utc>> {
    if value.trim().is_empty() {
        return None;
    }
    // Date-time strings without an offset are local time per ECMAScript.
    let millis = js_sys::Date::new(&JsValue::from_str(value)).get_time();
    if millis.is_nan() {
        return None;
    }
    DateTime::from_timestamp_millis(millis as i64)
}

/// "3 days ago" / "in 2 hours"
pub fn format_relative(time: DateTime<Utc>) -> String {
    let diff_ms = now_millis() - time.timestamp_millis() as f64;
    let future = diff_ms < 0.0;
    let seconds = (diff_ms.abs() / 1000.0) as i64;
    let (count, unit) = if seconds < 60 {
        return if future {
            "in under a minute"
        } else {
            "just now"
        }
        .to_string();
    } else if seconds < 3600 {
        (seconds / 60, "minute")
    } else if seconds < 86_400 {
        (seconds / 3600, "hour")
    } else if seconds < 30 * 86_400 {
        (seconds / 86_400, "day")
    } else if seconds < 365 * 86_400 {
        (seconds / (30 * 86_400), "month")
    } else {
        (seconds / (365 * 86_400), "year")
    };
    let plural = if count == 1 { "" } else { "s" };
    if future {
        format!("in {count} {unit}{plural}")
    } else {
        format!("{count} {unit}{plural} ago")
    }
}

pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value >= KIB * KIB * KIB {
        format!("{:.1} GiB", value / (KIB * KIB * KIB))
    } else if value >= KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else if value >= KIB {
        format!("{:.1} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}
