//! Entry types and operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A password entry in a KeePass database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unique identifier for this entry
    pub uuid: Uuid,
    /// Entry title (e.g., "GitHub Account")
    pub title: String,
    /// Username
    pub username: String,
    /// Password (protected, will be zeroed on drop)
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<SecureString>,
    /// URL associated with this entry
    pub url: String,
    /// Notes
    pub notes: String,
    /// Custom fields (key-value pairs)
    #[serde(default)]
    pub custom_fields: std::collections::HashMap<String, String>,
    /// Tags for organization
    #[serde(default)]
    pub tags: Vec<String>,
    /// Icon ID
    pub icon_id: Option<u32>,
    /// UUID of the parent group
    pub parent_group: Option<Uuid>,
    /// Creation time
    pub created: DateTime<Utc>,
    /// Last modification time
    pub modified: DateTime<Utc>,
    /// Last access time
    pub accessed: DateTime<Utc>,
    /// Expiry time (if set)
    pub expires: Option<DateTime<Utc>>,
    /// Whether expiry is enabled
    pub expires_enabled: bool,
}

/// A secure string that is zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureString(***)")
    }
}

impl Serialize for SecureString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as the actual string (for JSON export)
        // In production, you might want to mask this or skip entirely
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecureString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecureString(s))
    }
}

impl Entry {
    /// Create a new entry with the given title
    pub fn new(title: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            uuid: Uuid::new_v4(),
            title: title.into(),
            username: String::new(),
            password: None,
            url: String::new(),
            notes: String::new(),
            custom_fields: std::collections::HashMap::new(),
            tags: Vec::new(),
            icon_id: None,
            parent_group: None,
            created: now,
            modified: now,
            accessed: now,
            expires: None,
            expires_enabled: false,
        }
    }

    /// Set the password
    pub fn set_password(&mut self, password: impl Into<String>) {
        self.password = Some(SecureString::new(password));
        self.modified = Utc::now();
    }

    /// Get the password (if set)
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|s| s.as_str())
    }

    /// Clear the password from memory
    pub fn clear_password(&mut self) {
        self.password = None;
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        if !self.expires_enabled {
            return false;
        }
        self.expires.map(|exp| exp < Utc::now()).unwrap_or(false)
    }

    /// Update the accessed timestamp
    pub fn touch(&mut self) {
        self.accessed = Utc::now();
    }

    /// Mark as modified
    pub fn mark_modified(&mut self) {
        self.modified = Utc::now();
    }
}

/// Builder for creating entries
pub struct EntryBuilder {
    entry: Entry,
}

impl EntryBuilder {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            entry: Entry::new(title),
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.entry.username = username.into();
        self
    }

    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.entry.set_password(password);
        self
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.entry.url = url.into();
        self
    }

    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.entry.notes = notes.into();
        self
    }

    pub fn custom_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.entry.custom_fields.insert(key.into(), value.into());
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.entry.tags.push(tag.into());
        self
    }

    pub fn parent_group(mut self, group_uuid: Uuid) -> Self {
        self.entry.parent_group = Some(group_uuid);
        self
    }

    pub fn expires(mut self, expires: DateTime<Utc>) -> Self {
        self.entry.expires = Some(expires);
        self.entry.expires_enabled = true;
        self
    }

    pub fn build(self) -> Entry {
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_creation() {
        let entry = Entry::new("Test Entry");
        assert_eq!(entry.title, "Test Entry");
        assert!(entry.password().is_none());
    }

    #[test]
    fn test_entry_builder() {
        let entry = EntryBuilder::new("GitHub")
            .username("user@example.com")
            .password("secret123")
            .url("https://github.com")
            .notes("My GitHub account")
            .tag("work")
            .tag("dev")
            .custom_field("2FA", "enabled")
            .build();

        assert_eq!(entry.title, "GitHub");
        assert_eq!(entry.username, "user@example.com");
        assert_eq!(entry.password(), Some("secret123"));
        assert_eq!(entry.url, "https://github.com");
        assert_eq!(entry.tags, vec!["work", "dev"]);
        assert_eq!(entry.custom_fields.get("2FA"), Some(&"enabled".to_string()));
    }

    #[test]
    fn test_entry_expiry() {
        let mut entry = Entry::new("Test");
        assert!(!entry.is_expired());

        // Set expiry in the past
        entry.expires = Some(Utc::now() - chrono::Duration::hours(1));
        entry.expires_enabled = true;
        assert!(entry.is_expired());

        // Set expiry in the future
        entry.expires = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!entry.is_expired());
    }
}
