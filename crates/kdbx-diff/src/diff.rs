//! Database diff algorithms

use crate::types::{Conflict, DiffOperation, EntryDiff, FieldChange, GroupDiff, Side};
use kdbx_core::{Database, Entry, Group, Uuid};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Result of comparing two or three databases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseDiff {
    /// Entry-level differences
    pub entry_diffs: Vec<EntryDiff>,
    /// Group-level differences
    pub group_diffs: Vec<GroupDiff>,
    /// Conflicts requiring resolution
    pub conflicts: Vec<Conflict>,
    /// Summary statistics
    pub stats: DiffStats,
}

/// Statistics about the diff
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffStats {
    pub entries_added_left: usize,
    pub entries_added_right: usize,
    pub entries_modified: usize,
    pub entries_deleted: usize,
    pub entries_unchanged: usize,
    pub groups_added_left: usize,
    pub groups_added_right: usize,
    pub groups_modified: usize,
    pub groups_deleted: usize,
    pub conflict_count: usize,
}

impl DatabaseDiff {
    /// Perform a two-way diff between two databases
    ///
    /// This compares `left` and `right` directly without a common ancestor.
    /// Any differences are treated as potential conflicts.
    pub fn two_way(left: &Database, right: &Database) -> Self {
        let mut entry_diffs = Vec::new();
        let mut group_diffs = Vec::new();
        let mut conflicts = Vec::new();
        let mut stats = DiffStats::default();

        // Index entries by UUID
        let left_entries: HashMap<Uuid, &Entry> = left.entries().map(|e| (e.uuid, e)).collect();
        let right_entries: HashMap<Uuid, &Entry> = right.entries().map(|e| (e.uuid, e)).collect();

        // All UUIDs from both databases
        let all_uuids: HashSet<Uuid> = left_entries
            .keys()
            .chain(right_entries.keys())
            .copied()
            .collect();

        for uuid in all_uuids {
            let in_left = left_entries.get(&uuid);
            let in_right = right_entries.get(&uuid);

            match (in_left, in_right) {
                (Some(left_entry), Some(right_entry)) => {
                    // Entry in both - check for modifications
                    let field_changes = Self::compare_entries_two_way(left_entry, right_entry);

                    if field_changes.is_empty() {
                        stats.entries_unchanged += 1;
                    } else {
                        stats.entries_modified += 1;

                        // Create conflicts for any differences
                        for fc in &field_changes {
                            if fc.is_conflict {
                                conflicts.push(Conflict::from_field_change(
                                    uuid,
                                    &left_entry.title,
                                    fc,
                                ));
                            }
                        }

                        entry_diffs.push(EntryDiff {
                            uuid,
                            title: left_entry.title.clone(),
                            operation: DiffOperation::Modified {
                                left_modified: left_entry.modified,
                                right_modified: right_entry.modified,
                            },
                            field_changes,
                        });
                    }
                }
                (Some(left_entry), None) => {
                    // Only in left
                    stats.entries_added_left += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: left_entry.title.clone(),
                        operation: DiffOperation::AddedLeft,
                        field_changes: vec![],
                    });
                }
                (None, Some(right_entry)) => {
                    // Only in right
                    stats.entries_added_right += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: right_entry.title.clone(),
                        operation: DiffOperation::AddedRight,
                        field_changes: vec![],
                    });
                }
                (None, None) => unreachable!(),
            }
        }

        // Index groups by UUID
        let left_groups: HashMap<Uuid, &Group> = left.groups().map(|g| (g.uuid, g)).collect();
        let right_groups: HashMap<Uuid, &Group> = right.groups().map(|g| (g.uuid, g)).collect();

        let all_group_uuids: HashSet<Uuid> = left_groups
            .keys()
            .chain(right_groups.keys())
            .copied()
            .collect();

        for uuid in all_group_uuids {
            let in_left = left_groups.get(&uuid);
            let in_right = right_groups.get(&uuid);

            match (in_left, in_right) {
                (Some(left_group), Some(right_group)) => {
                    let field_changes = Self::compare_groups_two_way(left_group, right_group);
                    if !field_changes.is_empty() {
                        stats.groups_modified += 1;
                        group_diffs.push(GroupDiff {
                            uuid,
                            name: left_group.name.clone(),
                            operation: DiffOperation::Modified {
                                left_modified: left_group.modified,
                                right_modified: right_group.modified,
                            },
                            field_changes,
                        });
                    }
                }
                (Some(left_group), None) => {
                    stats.groups_added_left += 1;
                    group_diffs.push(GroupDiff {
                        uuid,
                        name: left_group.name.clone(),
                        operation: DiffOperation::AddedLeft,
                        field_changes: vec![],
                    });
                }
                (None, Some(right_group)) => {
                    stats.groups_added_right += 1;
                    group_diffs.push(GroupDiff {
                        uuid,
                        name: right_group.name.clone(),
                        operation: DiffOperation::AddedRight,
                        field_changes: vec![],
                    });
                }
                (None, None) => unreachable!(),
            }
        }

        stats.conflict_count = conflicts.len();

        Self {
            entry_diffs,
            group_diffs,
            conflicts,
            stats,
        }
    }

    /// Perform a three-way diff using a common ancestor
    ///
    /// This is the preferred method when you have a base version (e.g., the last
    /// synced state) and two divergent versions (local and remote).
    pub fn three_way(base: &Database, left: &Database, right: &Database) -> Self {
        let mut entry_diffs = Vec::new();
        let mut group_diffs = Vec::new();
        let mut conflicts = Vec::new();
        let mut stats = DiffStats::default();

        // Index entries by UUID
        let base_entries: HashMap<Uuid, &Entry> = base.entries().map(|e| (e.uuid, e)).collect();
        let left_entries: HashMap<Uuid, &Entry> = left.entries().map(|e| (e.uuid, e)).collect();
        let right_entries: HashMap<Uuid, &Entry> = right.entries().map(|e| (e.uuid, e)).collect();

        // All UUIDs from all three databases
        let all_uuids: HashSet<Uuid> = base_entries
            .keys()
            .chain(left_entries.keys())
            .chain(right_entries.keys())
            .copied()
            .collect();

        for uuid in all_uuids {
            let in_base = base_entries.get(&uuid);
            let in_left = left_entries.get(&uuid);
            let in_right = right_entries.get(&uuid);

            match (in_base, in_left, in_right) {
                // Entry in all three - check for modifications
                (Some(base_entry), Some(left_entry), Some(right_entry)) => {
                    let field_changes =
                        Self::compare_entries_three_way(base_entry, left_entry, right_entry);

                    let has_changes = !field_changes.is_empty();
                    let has_conflicts = field_changes.iter().any(|fc| fc.is_conflict);

                    if has_conflicts {
                        for fc in &field_changes {
                            if fc.is_conflict {
                                conflicts.push(Conflict::from_field_change(
                                    uuid,
                                    &left_entry.title,
                                    fc,
                                ));
                            }
                        }
                    }

                    if has_changes {
                        stats.entries_modified += 1;
                        entry_diffs.push(EntryDiff {
                            uuid,
                            title: left_entry.title.clone(),
                            operation: DiffOperation::Modified {
                                left_modified: left_entry.modified,
                                right_modified: right_entry.modified,
                            },
                            field_changes,
                        });
                    } else {
                        stats.entries_unchanged += 1;
                    }
                }

                // Added in left only (not in base, not in right)
                (None, Some(left_entry), None) => {
                    stats.entries_added_left += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: left_entry.title.clone(),
                        operation: DiffOperation::AddedLeft,
                        field_changes: vec![],
                    });
                }

                // Added in right only (not in base, not in left)
                (None, None, Some(right_entry)) => {
                    stats.entries_added_right += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: right_entry.title.clone(),
                        operation: DiffOperation::AddedRight,
                        field_changes: vec![],
                    });
                }

                // Added in both (not in base, in both left and right)
                (None, Some(left_entry), Some(right_entry)) => {
                    // Both added the same entry - check if they differ
                    let field_changes = Self::compare_entries_two_way(left_entry, right_entry);

                    if field_changes.is_empty() {
                        // Added identically - no conflict
                        stats.entries_added_left += 1;
                        entry_diffs.push(EntryDiff {
                            uuid,
                            title: left_entry.title.clone(),
                            operation: DiffOperation::AddedLeft, // Arbitrary choice
                            field_changes: vec![],
                        });
                    } else {
                        // Added differently - conflict
                        stats.entries_modified += 1;
                        for fc in &field_changes {
                            conflicts.push(Conflict::from_field_change(
                                uuid,
                                &left_entry.title,
                                fc,
                            ));
                        }
                        entry_diffs.push(EntryDiff {
                            uuid,
                            title: left_entry.title.clone(),
                            operation: DiffOperation::Modified {
                                left_modified: left_entry.modified,
                                right_modified: right_entry.modified,
                            },
                            field_changes,
                        });
                    }
                }

                // Deleted in left (was in base, still in right)
                (Some(base_entry), None, Some(_)) => {
                    stats.entries_deleted += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: base_entry.title.clone(),
                        operation: DiffOperation::Deleted {
                            deleted_in: Side::Left,
                        },
                        field_changes: vec![],
                    });
                }

                // Deleted in right (was in base, still in left)
                (Some(base_entry), Some(_), None) => {
                    stats.entries_deleted += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: base_entry.title.clone(),
                        operation: DiffOperation::Deleted {
                            deleted_in: Side::Right,
                        },
                        field_changes: vec![],
                    });
                }

                // Deleted in both (was in base, not in either)
                (Some(base_entry), None, None) => {
                    stats.entries_deleted += 1;
                    entry_diffs.push(EntryDiff {
                        uuid,
                        title: base_entry.title.clone(),
                        operation: DiffOperation::Deleted {
                            deleted_in: Side::Left, // Both deleted, arbitrary choice
                        },
                        field_changes: vec![],
                    });
                }

                // Not in any database (shouldn't happen)
                (None, None, None) => unreachable!(),
            }
        }

        // Similar logic for groups (simplified)
        let base_groups: HashMap<Uuid, &Group> = base.groups().map(|g| (g.uuid, g)).collect();
        let left_groups: HashMap<Uuid, &Group> = left.groups().map(|g| (g.uuid, g)).collect();
        let right_groups: HashMap<Uuid, &Group> = right.groups().map(|g| (g.uuid, g)).collect();

        let all_group_uuids: HashSet<Uuid> = base_groups
            .keys()
            .chain(left_groups.keys())
            .chain(right_groups.keys())
            .copied()
            .collect();

        for uuid in all_group_uuids {
            let in_base = base_groups.get(&uuid);
            let in_left = left_groups.get(&uuid);
            let in_right = right_groups.get(&uuid);

            match (in_base, in_left, in_right) {
                (Some(_), Some(left_group), Some(right_group)) => {
                    if left_group.name != right_group.name {
                        stats.groups_modified += 1;
                        group_diffs.push(GroupDiff {
                            uuid,
                            name: left_group.name.clone(),
                            operation: DiffOperation::Modified {
                                left_modified: left_group.modified,
                                right_modified: right_group.modified,
                            },
                            field_changes: vec![FieldChange::two_way(
                                "name",
                                Some(left_group.name.clone()),
                                Some(right_group.name.clone()),
                            )],
                        });
                    }
                }
                (None, Some(left_group), None) => {
                    stats.groups_added_left += 1;
                    group_diffs.push(GroupDiff {
                        uuid,
                        name: left_group.name.clone(),
                        operation: DiffOperation::AddedLeft,
                        field_changes: vec![],
                    });
                }
                (None, None, Some(right_group)) => {
                    stats.groups_added_right += 1;
                    group_diffs.push(GroupDiff {
                        uuid,
                        name: right_group.name.clone(),
                        operation: DiffOperation::AddedRight,
                        field_changes: vec![],
                    });
                }
                (Some(base_group), None, None) => {
                    stats.groups_deleted += 1;
                    group_diffs.push(GroupDiff {
                        uuid,
                        name: base_group.name.clone(),
                        operation: DiffOperation::Deleted {
                            deleted_in: Side::Left,
                        },
                        field_changes: vec![],
                    });
                }
                _ => {}
            }
        }

        stats.conflict_count = conflicts.len();

        Self {
            entry_diffs,
            group_diffs,
            conflicts,
            stats,
        }
    }

    /// Compare two entries field by field (two-way)
    fn compare_entries_two_way(left: &Entry, right: &Entry) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        // Compare standard fields
        if left.title != right.title {
            changes.push(FieldChange::two_way(
                "Title",
                Some(left.title.clone()),
                Some(right.title.clone()),
            ));
        }

        if left.username != right.username {
            changes.push(FieldChange::two_way(
                "UserName",
                Some(left.username.clone()),
                Some(right.username.clone()),
            ));
        }

        // Compare passwords (carefully)
        let left_pw = left.password().map(|s| s.to_string());
        let right_pw = right.password().map(|s| s.to_string());
        if left_pw != right_pw {
            changes.push(FieldChange::two_way("Password", left_pw, right_pw));
        }

        if left.url != right.url {
            changes.push(FieldChange::two_way(
                "URL",
                Some(left.url.clone()),
                Some(right.url.clone()),
            ));
        }

        if left.notes != right.notes {
            changes.push(FieldChange::two_way(
                "Notes",
                Some(left.notes.clone()),
                Some(right.notes.clone()),
            ));
        }

        // Compare custom fields
        let all_keys: HashSet<&String> = left
            .custom_fields
            .keys()
            .chain(right.custom_fields.keys())
            .collect();

        for key in all_keys {
            let left_val = left.custom_fields.get(key);
            let right_val = right.custom_fields.get(key);
            if left_val != right_val {
                changes.push(FieldChange::two_way(
                    key.clone(),
                    left_val.cloned(),
                    right_val.cloned(),
                ));
            }
        }

        changes
    }

    /// Compare three entries field by field (three-way)
    fn compare_entries_three_way(base: &Entry, left: &Entry, right: &Entry) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        // Helper macro to compare a field
        macro_rules! compare_field {
            ($field:ident, $name:literal) => {
                let base_val = Some(base.$field.clone());
                let left_val = Some(left.$field.clone());
                let right_val = Some(right.$field.clone());
                if left_val != base_val || right_val != base_val {
                    changes.push(FieldChange::three_way($name, base_val, left_val, right_val));
                }
            };
        }

        compare_field!(title, "Title");
        compare_field!(username, "UserName");
        compare_field!(url, "URL");
        compare_field!(notes, "Notes");

        // Password comparison
        let base_pw = base.password().map(|s| s.to_string());
        let left_pw = left.password().map(|s| s.to_string());
        let right_pw = right.password().map(|s| s.to_string());
        if left_pw != base_pw || right_pw != base_pw {
            changes.push(FieldChange::three_way(
                "Password", base_pw, left_pw, right_pw,
            ));
        }

        // Custom fields
        let all_keys: HashSet<&String> = base
            .custom_fields
            .keys()
            .chain(left.custom_fields.keys())
            .chain(right.custom_fields.keys())
            .collect();

        for key in all_keys {
            let base_val = base.custom_fields.get(key).cloned();
            let left_val = left.custom_fields.get(key).cloned();
            let right_val = right.custom_fields.get(key).cloned();

            if left_val != base_val || right_val != base_val {
                changes.push(FieldChange::three_way(
                    key.clone(),
                    base_val,
                    left_val,
                    right_val,
                ));
            }
        }

        changes
    }

    /// Compare two groups field by field (two-way)
    fn compare_groups_two_way(left: &Group, right: &Group) -> Vec<FieldChange> {
        let mut changes = Vec::new();

        if left.name != right.name {
            changes.push(FieldChange::two_way(
                "name",
                Some(left.name.clone()),
                Some(right.name.clone()),
            ));
        }

        if left.notes != right.notes {
            changes.push(FieldChange::two_way(
                "notes",
                Some(left.notes.clone()),
                Some(right.notes.clone()),
            ));
        }

        changes
    }

    /// Check if this diff has any conflicts
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    /// Get the number of changes (excluding unchanged entries)
    pub fn change_count(&self) -> usize {
        self.entry_diffs.len() + self.group_diffs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdbx_core::EntryBuilder;

    fn create_test_db(name: &str, password: &str) -> Database {
        Database::new(name, password)
    }

    #[test]
    fn test_two_way_diff_no_changes() {
        let db1 = create_test_db("Test", "pass");
        let db2 = create_test_db("Test", "pass");

        let diff = DatabaseDiff::two_way(&db1, &db2);
        assert!(!diff.has_conflicts());
        assert_eq!(diff.stats.entries_unchanged, 0);
    }

    #[test]
    fn test_two_way_diff_added_entry() {
        let mut db1 = create_test_db("Test", "pass");
        let db2 = create_test_db("Test", "pass");

        let entry = EntryBuilder::new("GitHub").username("user").build();
        db1.add_entry(entry);

        let diff = DatabaseDiff::two_way(&db1, &db2);
        assert_eq!(diff.stats.entries_added_left, 1);
        assert_eq!(diff.entry_diffs.len(), 1);
    }

    #[test]
    fn test_two_way_diff_modified_entry() {
        let mut db1 = create_test_db("Test", "pass");
        let mut db2 = create_test_db("Test", "pass");

        let entry1 = EntryBuilder::new("GitHub")
            .username("user1")
            .password("pass1")
            .build();
        let uuid = entry1.uuid;

        let mut entry2 = entry1.clone();
        entry2.username = "user2".to_string();

        db1.add_entry(entry1);

        // For db2, we need to add an entry with the same UUID
        let mut entry_for_db2 = Entry::new("GitHub");
        entry_for_db2.uuid = uuid;
        entry_for_db2.username = "user2".to_string();
        db2.add_entry(entry_for_db2);

        let diff = DatabaseDiff::two_way(&db1, &db2);
        assert!(diff.has_conflicts());
        assert_eq!(diff.stats.entries_modified, 1);
    }
}
