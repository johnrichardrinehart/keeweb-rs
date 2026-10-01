//! Public view, edit and change types. All of them serialize with serde so they can
//! cross the WASM boundary as JSON (UUIDs as hyphenated strings, times as RFC 3339).

use super::KdbxDocument;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringField {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimesView {
    pub creation: Option<DateTime<Utc>>,
    pub last_modification: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
    pub location_changed: Option<DateTime<Utc>>,
    pub usage_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentView {
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTypeAssociation {
    pub window: String,
    pub sequence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTypeEdit {
    pub enabled: bool,
    pub obfuscation: u32,
    pub default_sequence: String,
    pub associations: Vec<AutoTypeAssociation>,
}

impl Default for AutoTypeEdit {
    fn default() -> Self {
        Self {
            enabled: true,
            obfuscation: 0,
            default_sequence: String::new(),
            associations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryView {
    pub uuid: Uuid,
    /// Parent group. History versions report the group of their entry.
    pub group: Uuid,
    pub strings: Vec<StringField>,
    pub tags: Vec<String>,
    pub icon_id: u32,
    pub custom_icon: Option<Uuid>,
    pub foreground_color: String,
    pub background_color: String,
    pub override_url: String,
    pub expires: bool,
    pub expiry_time: Option<DateTime<Utc>>,
    pub times: TimesView,
    pub attachments: Vec<AttachmentView>,
    pub auto_type: AutoTypeEdit,
    /// Previous versions, oldest first. Always empty for history versions themselves.
    pub history: Vec<EntryView>,
    pub in_recycle_bin: bool,
}

impl EntryView {
    pub fn field(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|s| s.key == key)
            .map(|s| s.value.as_str())
    }

    pub fn title(&self) -> &str {
        self.field("Title").unwrap_or_default()
    }

    /// An edit that leaves the entry unchanged; attachments refer to their current names.
    pub fn to_edit(&self) -> EntryEdit {
        EntryEdit {
            strings: self.strings.clone(),
            tags: self.tags.clone(),
            icon_id: self.icon_id,
            custom_icon: self.custom_icon,
            foreground_color: self.foreground_color.clone(),
            background_color: self.background_color.clone(),
            override_url: self.override_url.clone(),
            expires: self.expires,
            expiry_time: self.expiry_time,
            attachments: self
                .attachments
                .iter()
                .map(|a| AttachmentEdit {
                    name: a.name.clone(),
                    data: AttachmentData::Existing(a.name.clone()),
                })
                .collect(),
            auto_type: self.auto_type.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentData {
    /// Keep the content of the attachment currently named so (allows renaming).
    Existing(String),
    New(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentEdit {
    pub name: String,
    pub data: AttachmentData,
}

/// Complete desired state of an entry's user-editable data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryEdit {
    pub strings: Vec<StringField>,
    pub tags: Vec<String>,
    pub icon_id: u32,
    pub custom_icon: Option<Uuid>,
    pub foreground_color: String,
    pub background_color: String,
    pub override_url: String,
    pub expires: bool,
    /// `None` keeps the stored expiry time.
    pub expiry_time: Option<DateTime<Utc>>,
    pub attachments: Vec<AttachmentEdit>,
    pub auto_type: AutoTypeEdit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    pub uuid: Uuid,
    /// `None` only for the root group.
    pub parent: Option<Uuid>,
    pub name: String,
    pub notes: String,
    pub icon_id: u32,
    pub custom_icon: Option<Uuid>,
    pub expires: bool,
    pub expiry_time: Option<DateTime<Utc>>,
    pub times: TimesView,
    pub is_expanded: bool,
    pub is_recycle_bin: bool,
    pub in_recycle_bin: bool,
}

impl GroupView {
    pub fn to_edit(&self) -> GroupEdit {
        GroupEdit {
            name: self.name.clone(),
            notes: self.notes.clone(),
            icon_id: self.icon_id,
            custom_icon: self.custom_icon,
            expires: self.expires,
            expiry_time: self.expiry_time,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupEdit {
    pub name: String,
    pub notes: String,
    pub icon_id: u32,
    pub custom_icon: Option<Uuid>,
    pub expires: bool,
    /// `None` keeps the stored expiry time.
    pub expiry_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaView {
    pub name: String,
    pub description: String,
    pub recycle_bin_enabled: bool,
    pub recycle_bin_uuid: Option<Uuid>,
    /// Negative means unlimited.
    pub history_max_items: i32,
    /// Bytes; negative means unlimited.
    pub history_max_size: i64,
}

impl MetaView {
    pub fn to_edit(&self) -> MetaEdit {
        MetaEdit {
            name: self.name.clone(),
            description: self.description.clone(),
            recycle_bin_enabled: self.recycle_bin_enabled,
            history_max_items: self.history_max_items,
            history_max_size: self.history_max_size,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaEdit {
    pub name: String,
    pub description: String,
    pub recycle_bin_enabled: bool,
    pub history_max_items: i32,
    pub history_max_size: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomIconView {
    pub uuid: Uuid,
    pub png: Vec<u8>,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    /// `ChangeOutcome::created` holds the new entry's UUID.
    CreateEntry {
        group: Uuid,
        entry: EntryEdit,
    },
    /// Pushes the previous version into the entry's history and applies the history limits.
    UpdateEntry {
        uuid: Uuid,
        entry: EntryEdit,
    },
    /// `ChangeOutcome::created` holds the copy's UUID.
    DuplicateEntry {
        uuid: Uuid,
    },
    MoveEntry {
        uuid: Uuid,
        group: Uuid,
    },
    /// Moves to the recycle bin (created on demand) when enabled and the entry is not
    /// already in it; otherwise deletes permanently and records a deleted object.
    DeleteEntry {
        uuid: Uuid,
    },
    RestoreHistory {
        uuid: Uuid,
        index: usize,
    },
    DeleteHistory {
        uuid: Uuid,
        index: usize,
    },
    /// `ChangeOutcome::created` holds the new group's UUID.
    CreateGroup {
        parent: Uuid,
        group: GroupEdit,
    },
    UpdateGroup {
        uuid: Uuid,
        group: GroupEdit,
    },
    MoveGroup {
        uuid: Uuid,
        parent: Uuid,
    },
    DeleteGroup {
        uuid: Uuid,
    },
    EmptyRecycleBin,
    /// `ChangeOutcome::created` holds the icon's UUID (an existing one for identical data).
    AddCustomIcon {
        png: Vec<u8>,
    },
    UpdateMeta {
        meta: MetaEdit,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeOutcome {
    /// Human-readable description without secrets: record titles and field names only.
    pub summary: String,
    pub created: Option<Uuid>,
    /// False when the change was a no-op and the document is unmodified.
    pub changed: bool,
}

pub struct MergeOutcome {
    pub document: KdbxDocument,
    /// Entry titles and group names changed differently on both sides. The losing
    /// version of each such entry is kept in its history.
    pub conflicts: Vec<String>,
}
