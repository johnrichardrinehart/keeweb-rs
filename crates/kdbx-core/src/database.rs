//! Database operations for KeePass files

use crate::entry::Entry;
use crate::error::{Error, Result};
use crate::group::Group;
use chrono::{DateTime, TimeZone, Utc};
use keepass::{Database as KpDatabase, DatabaseKey, db::Node};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Cursor;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A KeePass database with entries and groups
#[derive(Debug)]
pub struct Database {
    /// Database name
    pub name: String,
    /// Description
    pub description: String,
    /// All entries indexed by UUID
    entries: HashMap<Uuid, Entry>,
    /// All groups indexed by UUID
    groups: HashMap<Uuid, Group>,
    /// Root group UUID
    root_group: Uuid,
    /// Recycle bin group UUID (if enabled)
    #[allow(dead_code)]
    recycle_bin: Option<Uuid>,
    /// Whether recycle bin is enabled
    #[allow(dead_code)]
    recycle_bin_enabled: bool,
    /// The underlying keepass database (for saving)
    #[allow(dead_code)]
    inner: Option<KpDatabase>,
    /// Master password (kept for saving)
    master_password: Option<MasterPassword>,
}

/// Secure wrapper for master password
#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterPassword(String);

impl MasterPassword {
    fn new(password: impl Into<String>) -> Self {
        Self(password.into())
    }

    #[allow(dead_code)]
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterPassword(***)")
    }
}

/// Metadata about the database (for display without full unlock)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMetadata {
    pub name: String,
    pub description: String,
    pub entry_count: usize,
    pub group_count: usize,
}

impl Database {
    /// Create a new empty database with a master password
    pub fn new(name: impl Into<String>, password: impl Into<String>) -> Self {
        let root = Group::new("Root");
        let root_uuid = root.uuid;

        let mut groups = HashMap::new();
        groups.insert(root_uuid, root);

        Self {
            name: name.into(),
            description: String::new(),
            entries: HashMap::new(),
            groups,
            root_group: root_uuid,
            recycle_bin: None,
            recycle_bin_enabled: true,
            inner: None,
            master_password: Some(MasterPassword::new(password)),
        }
    }

    /// Open a database from bytes with a password
    pub fn open(data: &[u8], password: &str) -> Result<Self> {
        let key = DatabaseKey::new().with_password(password);
        let mut cursor = Cursor::new(data);

        let db = KpDatabase::open(&mut cursor, key).map_err(|e| Error::OpenError(e.to_string()))?;

        let mut database = Self::from_keepass_db(db)?;
        database.master_password = Some(MasterPassword::new(password));
        Ok(database)
    }

    /// Open a database from bytes with a password and optional keyfile
    pub fn open_with_keyfile(data: &[u8], password: &str, keyfile: Option<&[u8]>) -> Result<Self> {
        let mut key = DatabaseKey::new().with_password(password);

        if let Some(kf) = keyfile {
            let mut kf_cursor = Cursor::new(kf);
            key = key
                .with_keyfile(&mut kf_cursor)
                .map_err(|e| Error::OpenError(format!("Invalid keyfile: {}", e)))?;
        }

        let mut cursor = Cursor::new(data);
        let db = KpDatabase::open(&mut cursor, key).map_err(|e| Error::OpenError(e.to_string()))?;

        let mut database = Self::from_keepass_db(db)?;
        database.master_password = Some(MasterPassword::new(password));
        Ok(database)
    }

    /// Convert from keepass crate's Database type
    fn from_keepass_db(db: KpDatabase) -> Result<Self> {
        let mut entries = HashMap::new();
        let mut groups = HashMap::new();

        // Get database name and description from root group
        let name = db.root.name.clone();
        let description = db.root.notes.clone().unwrap_or_default();

        // Process the root group and all subgroups recursively
        let root_uuid = Self::process_group(&db.root, None, &mut groups, &mut entries);

        Ok(Self {
            name,
            description,
            entries,
            groups,
            root_group: root_uuid,
            recycle_bin: db.meta.recyclebin_uuid,
            recycle_bin_enabled: db.meta.recyclebin_enabled.unwrap_or(true),
            inner: Some(db),
            master_password: None,
        })
    }

    /// Recursively process a group and its contents
    fn process_group(
        kp_group: &keepass::db::Group,
        parent_uuid: Option<Uuid>,
        groups: &mut HashMap<Uuid, Group>,
        entries: &mut HashMap<Uuid, Entry>,
    ) -> Uuid {
        let group_uuid = kp_group.uuid;

        // Create our Group
        let mut group = Group::with_uuid(group_uuid, &kp_group.name);
        group.parent = parent_uuid;
        group.notes = kp_group.notes.clone().unwrap_or_default();

        // Process children (which can be entries or groups)
        for child in &kp_group.children {
            match child {
                Node::Entry(kp_entry) => {
                    let entry = Self::convert_entry(kp_entry, group_uuid);
                    let entry_uuid = entry.uuid;
                    entries.insert(entry_uuid, entry);
                    group.entries.push(entry_uuid);
                }
                Node::Group(child_group) => {
                    let child_uuid =
                        Self::process_group(child_group, Some(group_uuid), groups, entries);
                    group.children.push(child_uuid);
                }
            }
        }

        groups.insert(group_uuid, group);
        group_uuid
    }

    /// Convert a keepass entry to our Entry type
    fn convert_entry(kp_entry: &keepass::db::Entry, parent_group: Uuid) -> Entry {
        let entry_uuid = kp_entry.uuid;

        let mut entry = Entry::new(kp_entry.get_title().unwrap_or("Untitled"));
        entry.uuid = entry_uuid;
        entry.username = kp_entry.get_username().unwrap_or("").to_string();
        entry.url = kp_entry.get_url().unwrap_or("").to_string();
        entry.notes = kp_entry.get("Notes").unwrap_or("").to_string();
        entry.parent_group = Some(parent_group);

        // Set password if present
        if let Some(pw) = kp_entry.get_password() {
            entry.set_password(pw);
        }

        // Set timestamps from Times struct
        let times = &kp_entry.times;
        if let Some(created) = times.times.get("CreationTime") {
            entry.created = datetime_from_keepass(*created);
        }
        if let Some(modified) = times.times.get("LastModificationTime") {
            entry.modified = datetime_from_keepass(*modified);
        }
        if let Some(accessed) = times.times.get("LastAccessTime") {
            entry.accessed = datetime_from_keepass(*accessed);
        }
        if let Some(expires) = times.times.get("ExpiryTime") {
            entry.expires = Some(datetime_from_keepass(*expires));
        }
        entry.expires_enabled = times.expires;

        // Extract custom fields
        for (key, value) in kp_entry.fields.iter() {
            // Skip standard fields
            if !["Title", "UserName", "Password", "URL", "Notes"].contains(&key.as_str()) {
                if let keepass::db::Value::Unprotected(v) = value {
                    entry.custom_fields.insert(key.clone(), v.clone());
                }
            }
        }

        // Tags - KeePass uses semicolons, but some databases use commas
        if let Some(tags_str) = kp_entry.get("Tags") {
            // Try semicolon first (standard KeePass format), fall back to comma
            let separator = if tags_str.contains(';') { ';' } else { ',' };
            entry.tags = tags_str
                .split(separator)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        entry
    }

    /// Save the database to bytes
    /// Note: Requires the `save_kdbx4` feature on the keepass crate
    pub fn save(&self) -> Result<Vec<u8>> {
        // For now, saving is not fully supported without the save_kdbx4 feature
        // We'll need to reconstruct the database from our internal state
        Err(Error::SaveError(
            "Saving requires keepass crate with save_kdbx4 feature".to_string(),
        ))
    }

    /// Get database metadata
    pub fn metadata(&self) -> DatabaseMetadata {
        DatabaseMetadata {
            name: self.name.clone(),
            description: self.description.clone(),
            entry_count: self.entries.len(),
            group_count: self.groups.len(),
        }
    }

    /// Get the root group
    pub fn root_group(&self) -> &Group {
        self.groups
            .get(&self.root_group)
            .expect("Root group must exist")
    }

    /// Get all entries
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Get an entry by UUID
    pub fn get_entry(&self, uuid: &Uuid) -> Option<&Entry> {
        self.entries.get(uuid)
    }

    /// Get a mutable entry by UUID
    pub fn get_entry_mut(&mut self, uuid: &Uuid) -> Option<&mut Entry> {
        self.entries.get_mut(uuid)
    }

    /// Add an entry to the database
    pub fn add_entry(&mut self, mut entry: Entry) -> Uuid {
        let entry_uuid = entry.uuid;

        // Set parent group to root if not specified
        if entry.parent_group.is_none() {
            entry.parent_group = Some(self.root_group);
        }

        // Add entry UUID to parent group
        if let Some(parent_uuid) = entry.parent_group {
            if let Some(group) = self.groups.get_mut(&parent_uuid) {
                group.add_entry(entry_uuid);
            }
        }

        self.entries.insert(entry_uuid, entry);
        entry_uuid
    }

    /// Update an existing entry
    pub fn update_entry(&mut self, uuid: &Uuid, entry: Entry) -> Result<()> {
        if !self.entries.contains_key(uuid) {
            return Err(Error::EntryNotFound(*uuid));
        }
        self.entries.insert(*uuid, entry);
        Ok(())
    }

    /// Delete an entry
    pub fn delete_entry(&mut self, uuid: &Uuid) -> Result<Entry> {
        let entry = self
            .entries
            .remove(uuid)
            .ok_or(Error::EntryNotFound(*uuid))?;

        // Remove from parent group
        if let Some(parent_uuid) = entry.parent_group {
            if let Some(group) = self.groups.get_mut(&parent_uuid) {
                group.remove_entry(uuid);
            }
        }

        Ok(entry)
    }

    /// Get all groups
    pub fn groups(&self) -> impl Iterator<Item = &Group> {
        self.groups.values()
    }

    /// Get a group by UUID
    pub fn get_group(&self, uuid: &Uuid) -> Option<&Group> {
        self.groups.get(uuid)
    }

    /// Add a group to the database
    pub fn add_group(&mut self, mut group: Group) -> Uuid {
        let group_uuid = group.uuid;

        // Set parent group to root if not specified
        if group.parent.is_none() {
            group.parent = Some(self.root_group);
        }

        // Add group UUID to parent
        if let Some(parent_uuid) = group.parent {
            if let Some(parent) = self.groups.get_mut(&parent_uuid) {
                parent.add_child(group_uuid);
            }
        }

        self.groups.insert(group_uuid, group);
        group_uuid
    }

    /// Delete a group (moves contents to recycle bin or deletes permanently)
    pub fn delete_group(&mut self, uuid: &Uuid, _permanent: bool) -> Result<()> {
        if uuid == &self.root_group {
            return Err(Error::InvalidGroup("Cannot delete root group".to_string()));
        }

        let group = self
            .groups
            .remove(uuid)
            .ok_or(Error::GroupNotFound(*uuid))?;

        // Remove from parent
        if let Some(parent_uuid) = group.parent {
            if let Some(parent) = self.groups.get_mut(&parent_uuid) {
                parent.remove_child(uuid);
            }
        }

        // Delete all entries in this group
        for entry_uuid in &group.entries {
            self.entries.remove(entry_uuid);
        }

        // Recursively delete child groups
        for child_uuid in &group.children {
            let _ = self.delete_group(child_uuid, true);
        }

        Ok(())
    }

    /// Search entries by query
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let query_lower = query.to_lowercase();
        self.entries
            .values()
            .filter(|entry| {
                entry.title.to_lowercase().contains(&query_lower)
                    || entry.username.to_lowercase().contains(&query_lower)
                    || entry.url.to_lowercase().contains(&query_lower)
                    || entry.notes.to_lowercase().contains(&query_lower)
                    || entry
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    /// Get entries in a specific group
    pub fn entries_in_group(&self, group_uuid: &Uuid) -> Vec<&Entry> {
        self.groups
            .get(group_uuid)
            .map(|group| {
                group
                    .entries
                    .iter()
                    .filter_map(|uuid| self.entries.get(uuid))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the group tree structure (for sidebar display)
    pub fn group_tree(&self) -> GroupTreeNode {
        self.build_group_tree(&self.root_group)
    }

    fn build_group_tree(&self, uuid: &Uuid) -> GroupTreeNode {
        let group = self.groups.get(uuid).expect("Group must exist");

        GroupTreeNode {
            uuid: *uuid,
            name: group.name.clone(),
            entry_count: group.entries.len(),
            children: group
                .children
                .iter()
                .map(|child_uuid| self.build_group_tree(child_uuid))
                .collect(),
        }
    }
}

/// A tree node for displaying the group hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupTreeNode {
    pub uuid: Uuid,
    pub name: String,
    pub entry_count: usize,
    pub children: Vec<GroupTreeNode>,
}

/// Convert keepass datetime to chrono DateTime
fn datetime_from_keepass(kp_time: chrono::NaiveDateTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&kp_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = Database::new("My Passwords", "secret");
        assert_eq!(db.name, "My Passwords");
        assert!(db.entries().count() == 0);
        assert!(db.groups().count() == 1); // Root group
    }

    #[test]
    fn test_add_entry() {
        let mut db = Database::new("Test DB", "secret");
        let entry = Entry::new("GitHub");
        let uuid = db.add_entry(entry);

        assert!(db.get_entry(&uuid).is_some());
        assert_eq!(db.entries().count(), 1);
    }

    #[test]
    fn test_delete_entry() {
        let mut db = Database::new("Test DB", "secret");
        let entry = Entry::new("GitHub");
        let uuid = db.add_entry(entry);

        let deleted = db.delete_entry(&uuid);
        assert!(deleted.is_ok());
        assert!(db.get_entry(&uuid).is_none());
    }

    #[test]
    fn test_add_group() {
        let mut db = Database::new("Test DB", "secret");
        let group = Group::new("Work");
        let uuid = db.add_group(group);

        assert!(db.get_group(&uuid).is_some());
        assert_eq!(db.groups().count(), 2); // Root + Work
    }

    #[test]
    fn test_search() {
        let mut db = Database::new("Test DB", "secret");

        let mut entry1 = Entry::new("GitHub Account");
        entry1.username = "user@github.com".to_string();
        db.add_entry(entry1);

        let mut entry2 = Entry::new("Work Email");
        entry2.username = "user@work.com".to_string();
        db.add_entry(entry2);

        let results = db.search("github");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "GitHub Account");

        let results = db.search("user");
        assert_eq!(results.len(), 2);
    }
}
