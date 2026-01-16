//! Group types and operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A group (folder) in a KeePass database that contains entries and subgroups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for this group
    pub uuid: Uuid,
    /// Group name
    pub name: String,
    /// Notes for this group
    pub notes: String,
    /// Icon ID
    pub icon_id: Option<u32>,
    /// UUID of the parent group (None for root)
    pub parent: Option<Uuid>,
    /// UUIDs of child groups
    #[serde(default)]
    pub children: Vec<Uuid>,
    /// UUIDs of entries in this group
    #[serde(default)]
    pub entries: Vec<Uuid>,
    /// Creation time
    pub created: DateTime<Utc>,
    /// Last modification time
    pub modified: DateTime<Utc>,
    /// Whether this group is expanded in the UI
    pub expanded: bool,
    /// Default auto-type enabled for entries in this group
    pub default_auto_type_enabled: bool,
    /// Search enabled for this group
    pub search_enabled: bool,
}

impl Group {
    /// Create a new group with the given name
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            uuid: Uuid::new_v4(),
            name: name.into(),
            notes: String::new(),
            icon_id: None,
            parent: None,
            children: Vec::new(),
            entries: Vec::new(),
            created: now,
            modified: now,
            expanded: true,
            default_auto_type_enabled: true,
            search_enabled: true,
        }
    }

    /// Create a new group with a specific UUID (used when loading from database)
    pub fn with_uuid(uuid: Uuid, name: impl Into<String>) -> Self {
        let mut group = Self::new(name);
        group.uuid = uuid;
        group
    }

    /// Add a child group UUID
    pub fn add_child(&mut self, child_uuid: Uuid) {
        if !self.children.contains(&child_uuid) {
            self.children.push(child_uuid);
            self.modified = Utc::now();
        }
    }

    /// Remove a child group UUID
    pub fn remove_child(&mut self, child_uuid: &Uuid) -> bool {
        if let Some(pos) = self.children.iter().position(|u| u == child_uuid) {
            self.children.remove(pos);
            self.modified = Utc::now();
            true
        } else {
            false
        }
    }

    /// Add an entry UUID to this group
    pub fn add_entry(&mut self, entry_uuid: Uuid) {
        if !self.entries.contains(&entry_uuid) {
            self.entries.push(entry_uuid);
            self.modified = Utc::now();
        }
    }

    /// Remove an entry UUID from this group
    pub fn remove_entry(&mut self, entry_uuid: &Uuid) -> bool {
        if let Some(pos) = self.entries.iter().position(|u| u == entry_uuid) {
            self.entries.remove(pos);
            self.modified = Utc::now();
            true
        } else {
            false
        }
    }

    /// Check if this is a root group (no parent)
    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    /// Mark as modified
    pub fn mark_modified(&mut self) {
        self.modified = Utc::now();
    }
}

/// Builder for creating groups
pub struct GroupBuilder {
    group: Group,
}

impl GroupBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            group: Group::new(name),
        }
    }

    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.group.notes = notes.into();
        self
    }

    pub fn icon_id(mut self, icon_id: u32) -> Self {
        self.group.icon_id = Some(icon_id);
        self
    }

    pub fn parent(mut self, parent_uuid: Uuid) -> Self {
        self.group.parent = Some(parent_uuid);
        self
    }

    pub fn expanded(mut self, expanded: bool) -> Self {
        self.group.expanded = expanded;
        self
    }

    pub fn build(self) -> Group {
        self.group
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_creation() {
        let group = Group::new("My Passwords");
        assert_eq!(group.name, "My Passwords");
        assert!(group.is_root());
        assert!(group.children.is_empty());
        assert!(group.entries.is_empty());
    }

    #[test]
    fn test_group_builder() {
        let parent_uuid = Uuid::new_v4();
        let group = GroupBuilder::new("Work")
            .notes("Work-related passwords")
            .icon_id(48)
            .parent(parent_uuid)
            .expanded(false)
            .build();

        assert_eq!(group.name, "Work");
        assert_eq!(group.notes, "Work-related passwords");
        assert_eq!(group.icon_id, Some(48));
        assert_eq!(group.parent, Some(parent_uuid));
        assert!(!group.expanded);
    }

    #[test]
    fn test_group_children() {
        let mut group = Group::new("Parent");
        let child_uuid = Uuid::new_v4();

        group.add_child(child_uuid);
        assert_eq!(group.children.len(), 1);
        assert!(group.children.contains(&child_uuid));

        // Adding same child again should not duplicate
        group.add_child(child_uuid);
        assert_eq!(group.children.len(), 1);

        // Remove child
        assert!(group.remove_child(&child_uuid));
        assert!(group.children.is_empty());

        // Removing non-existent child returns false
        assert!(!group.remove_child(&child_uuid));
    }

    #[test]
    fn test_group_entries() {
        let mut group = Group::new("Parent");
        let entry_uuid = Uuid::new_v4();

        group.add_entry(entry_uuid);
        assert_eq!(group.entries.len(), 1);
        assert!(group.entries.contains(&entry_uuid));

        assert!(group.remove_entry(&entry_uuid));
        assert!(group.entries.is_empty());
    }
}
