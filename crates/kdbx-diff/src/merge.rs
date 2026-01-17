//! Database merge operations

use crate::diff::DatabaseDiff;
use crate::types::{Conflict, DiffOperation, Resolution, Side};
use kdbx_core::{Database, Entry, Group, Uuid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Merger for combining divergent databases
pub struct Merger {
    strategy: MergeStrategy,
}

/// Strategy for automatic conflict resolution
#[derive(Debug, Clone, Default)]
pub enum MergeStrategy {
    /// Always take the newest based on modification time
    #[default]
    TakeNewest,
    /// Always take the left (local) value
    TakeLeft,
    /// Always take the right (remote) value
    TakeRight,
    /// Union merge: include all entries from both sides
    Union,
    /// Require manual resolution for all conflicts
    Manual,
}

/// Result of a merge operation
#[derive(Debug, Serialize, Deserialize)]
pub struct MergeResult {
    /// Whether the merge was successful
    pub success: bool,
    /// Applied resolutions
    pub applied_resolutions: Vec<AppliedResolution>,
    /// Any remaining unresolved conflicts
    pub unresolved_conflicts: Vec<Conflict>,
    /// Statistics about the merge
    pub stats: MergeStats,
}

/// A resolution that was applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedResolution {
    pub conflict_id: Uuid,
    pub entry_uuid: Uuid,
    pub field_name: String,
    pub resolution: Resolution,
    pub final_value: Option<String>,
}

/// Statistics about the merge
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MergeStats {
    pub entries_from_left: usize,
    pub entries_from_right: usize,
    pub entries_merged: usize,
    pub entries_deleted: usize,
    pub conflicts_resolved: usize,
    pub conflicts_remaining: usize,
}

impl Default for Merger {
    fn default() -> Self {
        Self::new()
    }
}

impl Merger {
    /// Create a new merger with default settings (TakeNewest strategy)
    pub fn new() -> Self {
        Self {
            strategy: MergeStrategy::TakeNewest,
        }
    }

    /// Set the merge strategy
    pub fn with_strategy(mut self, strategy: MergeStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Perform a three-way merge with user-provided resolutions
    ///
    /// # Arguments
    /// * `base` - The common ancestor database
    /// * `left` - The local/current database
    /// * `right` - The remote/incoming database
    /// * `resolutions` - User-provided resolutions for conflicts (conflict_id -> resolution)
    ///
    /// # Returns
    /// A new merged database and merge statistics
    pub fn merge_three_way(
        &self,
        base: &Database,
        left: &Database,
        right: &Database,
        resolutions: &HashMap<Uuid, Resolution>,
    ) -> (Database, MergeResult) {
        // Compute the diff
        let diff = DatabaseDiff::three_way(base, left, right);

        // Start with a clone of left as our base for merging
        // We'll apply changes from right and resolutions
        let mut merged = Database::new(&left.name, ""); // Password will be set by caller
        let mut stats = MergeStats::default();
        let mut applied_resolutions = Vec::new();
        let mut unresolved_conflicts = Vec::new();

        // Index entries for quick lookup
        let base_entries: HashMap<Uuid, &Entry> = base.entries().map(|e| (e.uuid, e)).collect();
        let left_entries: HashMap<Uuid, &Entry> = left.entries().map(|e| (e.uuid, e)).collect();
        let right_entries: HashMap<Uuid, &Entry> = right.entries().map(|e| (e.uuid, e)).collect();

        // Process each entry diff
        for entry_diff in &diff.entry_diffs {
            match &entry_diff.operation {
                DiffOperation::AddedLeft => {
                    // Entry added in left only - include it
                    if let Some(entry) = left_entries.get(&entry_diff.uuid) {
                        merged.add_entry((*entry).clone());
                        stats.entries_from_left += 1;
                    }
                }
                DiffOperation::AddedRight => {
                    // Entry added in right only - include it
                    if let Some(entry) = right_entries.get(&entry_diff.uuid) {
                        merged.add_entry((*entry).clone());
                        stats.entries_from_right += 1;
                    }
                }
                DiffOperation::Deleted { deleted_in } => {
                    // Entry was deleted in one side
                    // Default behavior: honor the deletion unless strategy is Union
                    match self.strategy {
                        MergeStrategy::Union => {
                            // In union mode, keep entries that exist in either side
                            let entry = match deleted_in {
                                Side::Left => right_entries.get(&entry_diff.uuid),
                                Side::Right => left_entries.get(&entry_diff.uuid),
                                Side::Base => None,
                            };
                            if let Some(e) = entry {
                                merged.add_entry((*e).clone());
                            }
                        }
                        _ => {
                            // Honor deletion
                            stats.entries_deleted += 1;
                        }
                    }
                }
                DiffOperation::Modified {
                    left_modified,
                    right_modified,
                } => {
                    // Entry modified in both - need to merge field by field
                    let _base_entry = base_entries.get(&entry_diff.uuid);
                    let left_entry = left_entries.get(&entry_diff.uuid);
                    let right_entry = right_entries.get(&entry_diff.uuid);

                    if let (Some(left_e), Some(_right_e)) = (left_entry, right_entry) {
                        let mut merged_entry = (*left_e).clone();
                        let left_newer = left_modified > right_modified;

                        // Process each field change
                        for field_change in &entry_diff.field_changes {
                            if field_change.is_conflict {
                                // Look for user-provided resolution
                                let resolution = diff
                                    .conflicts
                                    .iter()
                                    .find(|c| {
                                        c.entry_uuid == entry_diff.uuid
                                            && c.field_name == field_change.field_name
                                    })
                                    .and_then(|conflict| resolutions.get(&conflict.id));

                                if let Some(res) = resolution {
                                    // Apply user resolution
                                    let conflict = Conflict::from_field_change(
                                        entry_diff.uuid,
                                        &entry_diff.title,
                                        field_change,
                                    );
                                    let final_value = res.apply(&conflict, left_newer);

                                    Self::apply_field_value(
                                        &mut merged_entry,
                                        &field_change.field_name,
                                        final_value.clone(),
                                    );

                                    applied_resolutions.push(AppliedResolution {
                                        conflict_id: conflict.id,
                                        entry_uuid: entry_diff.uuid,
                                        field_name: field_change.field_name.clone(),
                                        resolution: res.clone(),
                                        final_value,
                                    });
                                    stats.conflicts_resolved += 1;
                                } else {
                                    // No resolution provided - use strategy
                                    let final_value = match self.strategy {
                                        MergeStrategy::TakeNewest => {
                                            if left_newer {
                                                field_change.left_value.clone()
                                            } else {
                                                field_change.right_value.clone()
                                            }
                                        }
                                        MergeStrategy::TakeLeft => field_change.left_value.clone(),
                                        MergeStrategy::TakeRight => {
                                            field_change.right_value.clone()
                                        }
                                        MergeStrategy::Manual => {
                                            // Can't resolve - add to unresolved
                                            unresolved_conflicts.push(Conflict::from_field_change(
                                                entry_diff.uuid,
                                                &entry_diff.title,
                                                field_change,
                                            ));
                                            stats.conflicts_remaining += 1;
                                            continue;
                                        }
                                        MergeStrategy::Union => {
                                            // Take newest for union strategy
                                            if left_newer {
                                                field_change.left_value.clone()
                                            } else {
                                                field_change.right_value.clone()
                                            }
                                        }
                                    };

                                    Self::apply_field_value(
                                        &mut merged_entry,
                                        &field_change.field_name,
                                        final_value,
                                    );
                                    stats.conflicts_resolved += 1;
                                }
                            } else {
                                // Not a conflict - auto-resolve
                                if let Some(value) = field_change.auto_resolve() {
                                    Self::apply_field_value(
                                        &mut merged_entry,
                                        &field_change.field_name,
                                        Some(value.to_string()),
                                    );
                                }
                            }
                        }

                        merged.add_entry(merged_entry);
                        stats.entries_merged += 1;
                    }
                }
                DiffOperation::Unchanged => {
                    // No changes - take from left
                    if let Some(entry) = left_entries.get(&entry_diff.uuid) {
                        merged.add_entry((*entry).clone());
                    }
                }
                DiffOperation::Moved { .. } => {
                    // Handle moves by taking the entry from whichever side has it
                    if let Some(entry) = left_entries.get(&entry_diff.uuid) {
                        merged.add_entry((*entry).clone());
                    } else if let Some(entry) = right_entries.get(&entry_diff.uuid) {
                        merged.add_entry((*entry).clone());
                    }
                }
            }
        }

        // Process groups similarly (simplified - just merge group structures)
        let left_groups: HashMap<Uuid, &Group> = left.groups().map(|g| (g.uuid, g)).collect();
        let right_groups: HashMap<Uuid, &Group> = right.groups().map(|g| (g.uuid, g)).collect();

        for group_diff in &diff.group_diffs {
            match &group_diff.operation {
                DiffOperation::AddedLeft => {
                    if let Some(group) = left_groups.get(&group_diff.uuid) {
                        merged.add_group((*group).clone());
                    }
                }
                DiffOperation::AddedRight => {
                    if let Some(group) = right_groups.get(&group_diff.uuid) {
                        merged.add_group((*group).clone());
                    }
                }
                _ => {
                    // For modified/unchanged groups, take from left
                    if let Some(group) = left_groups.get(&group_diff.uuid) {
                        merged.add_group((*group).clone());
                    }
                }
            }
        }

        let result = MergeResult {
            success: unresolved_conflicts.is_empty(),
            applied_resolutions,
            unresolved_conflicts,
            stats,
        };

        (merged, result)
    }

    /// Apply a value to a specific field of an entry
    fn apply_field_value(entry: &mut Entry, field_name: &str, value: Option<String>) {
        match field_name {
            "Title" => {
                if let Some(v) = value {
                    entry.title = v;
                }
            }
            "UserName" => {
                if let Some(v) = value {
                    entry.username = v;
                }
            }
            "Password" => {
                if let Some(v) = value {
                    entry.set_password(v);
                } else {
                    entry.clear_password();
                }
            }
            "URL" => {
                if let Some(v) = value {
                    entry.url = v;
                }
            }
            "Notes" => {
                if let Some(v) = value {
                    entry.notes = v;
                }
            }
            _ => {
                // Custom field
                if let Some(v) = value {
                    entry.custom_fields.insert(field_name.to_string(), v);
                } else {
                    entry.custom_fields.remove(field_name);
                }
            }
        }
        entry.mark_modified();
    }

    /// Perform a simple two-way merge (when no base is available)
    ///
    /// This is less accurate than three-way merge and may produce more conflicts.
    pub fn merge_two_way(
        &self,
        left: &Database,
        right: &Database,
        resolutions: &HashMap<Uuid, Resolution>,
    ) -> (Database, MergeResult) {
        // For two-way merge, use left as the "base" for the three-way algorithm
        // This means:
        // - Entries only in right are "added in right"
        // - Entries only in left are "added in left"
        // - Entries in both with differences are conflicts

        // Create an empty base
        let empty_base = Database::new("empty", "");

        // Use three-way with empty base
        // Note: This isn't perfect but handles the common cases
        self.merge_three_way(&empty_base, left, right, resolutions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdbx_core::EntryBuilder;

    #[test]
    fn test_merge_no_conflicts() {
        let base = Database::new("Test", "pass");
        let mut left = Database::new("Test", "pass");
        let mut right = Database::new("Test", "pass");

        // Add different entries to each
        let entry_left = EntryBuilder::new("Left Entry").build();
        let entry_right = EntryBuilder::new("Right Entry").build();

        left.add_entry(entry_left);
        right.add_entry(entry_right);

        let merger = Merger::new();
        let (merged, result) = merger.merge_three_way(&base, &left, &right, &HashMap::new());

        assert!(result.success);
        assert_eq!(result.stats.entries_from_left, 1);
        assert_eq!(result.stats.entries_from_right, 1);
        assert_eq!(merged.entries().count(), 2);
    }

    #[test]
    fn test_merge_with_strategy() {
        let base = Database::new("Test", "pass");
        let left = Database::new("Test", "pass");
        let right = Database::new("Test", "pass");

        let merger = Merger::new().with_strategy(MergeStrategy::TakeLeft);
        let (_merged, result) = merger.merge_three_way(&base, &left, &right, &HashMap::new());

        assert!(result.success);
    }
}
