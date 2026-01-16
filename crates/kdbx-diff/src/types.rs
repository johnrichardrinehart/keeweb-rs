//! Types for diff and merge operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Which side of the diff an operation refers to
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    /// The "left" database (usually local/current)
    Left,
    /// The "right" database (usually remote/incoming)
    Right,
    /// The base/ancestor database (for three-way merges)
    Base,
}

/// Represents a difference operation for an entry or group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiffOperation {
    /// Item exists only in the left database (added locally or deleted remotely)
    AddedLeft,
    /// Item exists only in the right database (added remotely or deleted locally)
    AddedRight,
    /// Item was modified (exists in both but differs)
    Modified {
        left_modified: DateTime<Utc>,
        right_modified: DateTime<Utc>,
    },
    /// Item was deleted in one side
    Deleted { deleted_in: Side },
    /// Item was moved to a different group
    Moved {
        from_group: Uuid,
        to_group: Uuid,
        moved_in: Side,
    },
    /// Item is unchanged
    Unchanged,
}

/// A change to a specific field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    /// Name of the field (e.g., "Title", "Password", "URL")
    pub field_name: String,
    /// Value in base (for three-way diff)
    pub base_value: Option<String>,
    /// Value in left database
    pub left_value: Option<String>,
    /// Value in right database
    pub right_value: Option<String>,
    /// Whether this is a conflict (both sides changed differently from base)
    pub is_conflict: bool,
}

impl FieldChange {
    /// Create a field change for a two-way diff
    pub fn two_way(
        field_name: impl Into<String>,
        left: Option<String>,
        right: Option<String>,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            base_value: None,
            left_value: left,
            right_value: right,
            is_conflict: true, // In two-way diff, any difference is a potential conflict
        }
    }

    /// Create a field change for a three-way diff
    pub fn three_way(
        field_name: impl Into<String>,
        base: Option<String>,
        left: Option<String>,
        right: Option<String>,
    ) -> Self {
        // Determine if this is a conflict:
        // - Both changed from base in different ways = conflict
        // - Only one changed = not a conflict (take the change)
        // - Neither changed = not a conflict (take base)
        // - Both changed to same value = not a conflict (take either)
        let left_changed = left != base;
        let right_changed = right != base;
        let is_conflict = left_changed && right_changed && left != right;

        Self {
            field_name: field_name.into(),
            base_value: base,
            left_value: left,
            right_value: right,
            is_conflict,
        }
    }

    /// Get the automatically resolved value (if not a conflict)
    pub fn auto_resolve(&self) -> Option<&str> {
        if self.is_conflict {
            return None;
        }

        // If only left changed, take left
        if self.left_value != self.base_value && self.right_value == self.base_value {
            return self.left_value.as_deref();
        }

        // If only right changed, take right
        if self.right_value != self.base_value && self.left_value == self.base_value {
            return self.right_value.as_deref();
        }

        // If both are the same (either unchanged or changed to same value)
        self.left_value.as_deref()
    }
}

/// Diff result for a single entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryDiff {
    /// UUID of the entry
    pub uuid: Uuid,
    /// Title (for display purposes)
    pub title: String,
    /// The type of operation
    pub operation: DiffOperation,
    /// Field-level changes (if modified)
    pub field_changes: Vec<FieldChange>,
}

impl EntryDiff {
    /// Check if this entry diff has any conflicts
    pub fn has_conflicts(&self) -> bool {
        self.field_changes.iter().any(|fc| fc.is_conflict)
    }

    /// Get all field conflicts
    pub fn conflicts(&self) -> Vec<&FieldChange> {
        self.field_changes
            .iter()
            .filter(|fc| fc.is_conflict)
            .collect()
    }
}

/// Diff result for a single group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDiff {
    /// UUID of the group
    pub uuid: Uuid,
    /// Name (for display purposes)
    pub name: String,
    /// The type of operation
    pub operation: DiffOperation,
    /// Field-level changes (if modified)
    pub field_changes: Vec<FieldChange>,
}

/// A conflict that requires user resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    /// Unique ID for this conflict
    pub id: Uuid,
    /// UUID of the entry this conflict belongs to
    pub entry_uuid: Uuid,
    /// Entry title (for display)
    pub entry_title: String,
    /// Field name
    pub field_name: String,
    /// Value in base database
    pub base_value: Option<String>,
    /// Value in left database
    pub left_value: Option<String>,
    /// Value in right database
    pub right_value: Option<String>,
    /// Suggested resolution
    pub suggested_resolution: Resolution,
}

impl Conflict {
    /// Create a new conflict from a field change
    pub fn from_field_change(
        entry_uuid: Uuid,
        entry_title: impl Into<String>,
        field_change: &FieldChange,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            entry_uuid,
            entry_title: entry_title.into(),
            field_name: field_change.field_name.clone(),
            base_value: field_change.base_value.clone(),
            left_value: field_change.left_value.clone(),
            right_value: field_change.right_value.clone(),
            suggested_resolution: Resolution::TakeNewest, // Default suggestion
        }
    }
}

/// How to resolve a conflict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resolution {
    /// Take the left (local) value
    TakeLeft,
    /// Take the right (remote) value
    TakeRight,
    /// Take the base (original) value
    TakeBase,
    /// Automatically take the newest based on modification time
    TakeNewest,
    /// Use a manually specified value
    Manual(String),
}

impl Resolution {
    /// Apply this resolution to get the final value
    pub fn apply(&self, conflict: &Conflict, left_newer: bool) -> Option<String> {
        match self {
            Resolution::TakeLeft => conflict.left_value.clone(),
            Resolution::TakeRight => conflict.right_value.clone(),
            Resolution::TakeBase => conflict.base_value.clone(),
            Resolution::TakeNewest => {
                if left_newer {
                    conflict.left_value.clone()
                } else {
                    conflict.right_value.clone()
                }
            }
            Resolution::Manual(value) => Some(value.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_change_two_way() {
        let change =
            FieldChange::two_way("Password", Some("old".to_string()), Some("new".to_string()));
        assert!(change.is_conflict);
        assert_eq!(change.field_name, "Password");
    }

    #[test]
    fn test_field_change_three_way_no_conflict() {
        // Only left changed
        let change = FieldChange::three_way(
            "Password",
            Some("base".to_string()),
            Some("left_changed".to_string()),
            Some("base".to_string()),
        );
        assert!(!change.is_conflict);
        assert_eq!(change.auto_resolve(), Some("left_changed"));

        // Only right changed
        let change = FieldChange::three_way(
            "Password",
            Some("base".to_string()),
            Some("base".to_string()),
            Some("right_changed".to_string()),
        );
        assert!(!change.is_conflict);
        assert_eq!(change.auto_resolve(), Some("right_changed"));

        // Both changed to same value
        let change = FieldChange::three_way(
            "Password",
            Some("base".to_string()),
            Some("same".to_string()),
            Some("same".to_string()),
        );
        assert!(!change.is_conflict);
    }

    #[test]
    fn test_field_change_three_way_conflict() {
        // Both changed differently
        let change = FieldChange::three_way(
            "Password",
            Some("base".to_string()),
            Some("left_changed".to_string()),
            Some("right_changed".to_string()),
        );
        assert!(change.is_conflict);
        assert!(change.auto_resolve().is_none());
    }

    #[test]
    fn test_resolution_apply() {
        let conflict = Conflict {
            id: Uuid::new_v4(),
            entry_uuid: Uuid::new_v4(),
            entry_title: "Test".to_string(),
            field_name: "Password".to_string(),
            base_value: Some("base".to_string()),
            left_value: Some("left".to_string()),
            right_value: Some("right".to_string()),
            suggested_resolution: Resolution::TakeNewest,
        };

        assert_eq!(
            Resolution::TakeLeft.apply(&conflict, true),
            Some("left".to_string())
        );
        assert_eq!(
            Resolution::TakeRight.apply(&conflict, true),
            Some("right".to_string())
        );
        assert_eq!(
            Resolution::TakeBase.apply(&conflict, true),
            Some("base".to_string())
        );
        assert_eq!(
            Resolution::TakeNewest.apply(&conflict, true),
            Some("left".to_string())
        );
        assert_eq!(
            Resolution::TakeNewest.apply(&conflict, false),
            Some("right".to_string())
        );
        assert_eq!(
            Resolution::Manual("custom".to_string()).apply(&conflict, true),
            Some("custom".to_string())
        );
    }
}
