//! Editing operations behind [`KdbxDocument::apply`].
//!
//! Each operation only rewrites the parts of the tree it changes, so untouched
//! elements (including unknown ones) keep their content and position.

use super::values::{format_bool, format_tags, format_time, format_uuid, now};
use super::*;
use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashSet};

// Canonical child order, used only to position elements that have to be created.
pub(crate) const ENTRY_ORDER: &[&str] = &[
    "UUID",
    "IconID",
    "CustomIconUUID",
    "ForegroundColor",
    "BackgroundColor",
    "OverrideURL",
    "QualityCheck",
    "Tags",
    "PreviousParentGroup",
    "Times",
    "String",
    "Binary",
    "AutoType",
    "CustomData",
    "History",
];
pub(crate) const GROUP_ORDER: &[&str] = &[
    "UUID",
    "Name",
    "Notes",
    "IconID",
    "CustomIconUUID",
    "Times",
    "IsExpanded",
    "DefaultAutoTypeSequence",
    "EnableAutoType",
    "EnableSearching",
    "LastTopVisibleEntry",
    "PreviousParentGroup",
    "Tags",
    "CustomData",
    "Entry",
    "Group",
];
pub(crate) const TIMES_ORDER: &[&str] = &[
    "CreationTime",
    "LastModificationTime",
    "LastAccessTime",
    "ExpiryTime",
    "Expires",
    "UsageCount",
    "LocationChanged",
];
pub(crate) const META_ORDER: &[&str] = &[
    "Generator",
    "HeaderHash",
    "SettingsChanged",
    "DatabaseName",
    "DatabaseNameChanged",
    "DatabaseDescription",
    "DatabaseDescriptionChanged",
    "DefaultUserName",
    "DefaultUserNameChanged",
    "MaintenanceHistoryDays",
    "Color",
    "MasterKeyChanged",
    "MasterKeyChangeRec",
    "MasterKeyChangeForce",
    "MemoryProtection",
    "CustomIcons",
    "RecycleBinEnabled",
    "RecycleBinUUID",
    "RecycleBinChanged",
    "EntryTemplatesGroup",
    "EntryTemplatesGroupChanged",
    "HistoryMaxItems",
    "HistoryMaxSize",
    "LastSelectedGroup",
    "LastTopVisibleGroup",
    "Binaries",
    "CustomData",
];
pub(crate) const ROOT_ORDER: &[&str] = &["Group", "DeletedObjects"];
const AUTO_TYPE_ORDER: &[&str] = &[
    "Enabled",
    "DataTransferObfuscation",
    "DefaultSequence",
    "Association",
];
const KEY_VALUE_ORDER: &[&str] = &["Key", "Value"];

/// KeePass icon ids for new groups and the recycle bin.
const ICON_FOLDER: u32 = 48;
const ICON_RECYCLE_BIN: u32 = 43;

fn changed(summary: String, created: Option<Uuid>) -> ChangeOutcome {
    ChangeOutcome {
        summary,
        created,
        changed: true,
    }
}

fn unchanged(summary: String) -> ChangeOutcome {
    ChangeOutcome {
        summary,
        created: None,
        changed: false,
    }
}

pub(crate) fn order_of(element: &Element) -> &'static [&'static str] {
    match element.name.as_str() {
        "Entry" => ENTRY_ORDER,
        "Group" => GROUP_ORDER,
        _ => &[],
    }
}

pub(crate) fn set_times(element: &mut Element, names: &[&str], time: DateTime<Utc>) {
    let order = order_of(element);
    let times = element.ensure_child("Times", order);
    let text = format_time(time);
    for name in names {
        times.set_child_text(name, &text, TIMES_ORDER);
    }
}

fn touch_modified(element: &mut Element, now: DateTime<Utc>) {
    set_times(element, &["LastModificationTime", "LastAccessTime"], now);
}

fn new_times(now: DateTime<Utc>) -> Element {
    let t = format_time(now);
    Element::with_children(
        "Times",
        vec![
            Element::with_text("CreationTime", t.clone()),
            Element::with_text("LastModificationTime", t.clone()),
            Element::with_text("LastAccessTime", t.clone()),
            Element::with_text("ExpiryTime", t.clone()),
            Element::with_text("Expires", "False"),
            Element::with_text("UsageCount", "0"),
            Element::with_text("LocationChanged", t),
        ],
    )
}

fn new_entry_element(uuid: Uuid, now: DateTime<Utc>) -> Element {
    Element::with_children(
        "Entry",
        vec![
            Element::with_text("UUID", format_uuid(uuid)),
            Element::with_text("IconID", "0"),
            Element::new("ForegroundColor"),
            Element::new("BackgroundColor"),
            Element::new("OverrideURL"),
            Element::new("Tags"),
            new_times(now),
            Element::with_children(
                "AutoType",
                vec![
                    Element::with_text("Enabled", "True"),
                    Element::with_text("DataTransferObfuscation", "0"),
                ],
            ),
            Element::new("History"),
        ],
    )
}

fn new_group_element(uuid: Uuid, now: DateTime<Utc>) -> Element {
    Element::with_children(
        "Group",
        vec![
            Element::with_text("UUID", format_uuid(uuid)),
            Element::new("Name"),
            Element::new("Notes"),
            Element::with_text("IconID", ICON_FOLDER.to_string()),
            new_times(now),
            Element::with_text("IsExpanded", "True"),
            Element::new("DefaultAutoTypeSequence"),
            Element::with_text("EnableAutoType", "null"),
            Element::with_text("EnableSearching", "null"),
            Element::with_text("LastTopVisibleEntry", format_uuid(Uuid::nil())),
        ],
    )
}

/// The current state of an entry as an edit.
fn entry_edit_of(entry: &Element) -> EntryEdit {
    let (icon_id, custom_icon) = icon_of(entry);
    let (expires, expiry_time) = expiry_of(entry);
    EntryEdit {
        strings: strings_of(entry),
        tags: parse_tags(entry.child_text("Tags").unwrap_or_default()),
        icon_id,
        custom_icon,
        foreground_color: entry
            .child_text("ForegroundColor")
            .unwrap_or_default()
            .to_string(),
        background_color: entry
            .child_text("BackgroundColor")
            .unwrap_or_default()
            .to_string(),
        override_url: entry
            .child_text("OverrideURL")
            .unwrap_or_default()
            .to_string(),
        expires,
        expiry_time,
        attachments: binary_refs_of(entry)
            .into_iter()
            .map(|(name, _)| AttachmentEdit {
                data: AttachmentData::Existing(name.clone()),
                name,
            })
            .collect(),
        auto_type: auto_type_of(entry),
    }
}

fn expiry_changed(old: (bool, Option<DateTime<Utc>>), new: (bool, Option<DateTime<Utc>>)) -> bool {
    old.0 != new.0 || new.1.is_some_and(|t| Some(t) != old.1)
}

/// Changed string keys (sorted), followed by labels of other changed properties.
fn entry_changes(old: &EntryEdit, new: &EntryEdit) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for field in &new.strings {
        if old.strings.iter().find(|o| o.key == field.key) != Some(field) {
            keys.insert(field.key.as_str());
        }
    }
    for field in &old.strings {
        if !new.strings.iter().any(|n| n.key == field.key) {
            keys.insert(field.key.as_str());
        }
    }
    let mut labels: Vec<String> = keys.into_iter().map(str::to_string).collect();
    let mut push = |condition: bool, label: &str| {
        if condition {
            labels.push(label.to_string());
        }
    };
    push(old.tags != new.tags, "Tags");
    push(
        old.icon_id != new.icon_id || old.custom_icon != new.custom_icon,
        "Icon",
    );
    push(
        old.foreground_color != new.foreground_color
            || old.background_color != new.background_color,
        "Colors",
    );
    push(old.override_url != new.override_url, "Override URL");
    push(
        expiry_changed(
            (old.expires, old.expiry_time),
            (new.expires, new.expiry_time),
        ),
        "Expiry",
    );
    push(old.attachments != new.attachments, "Attachments");
    push(old.auto_type != new.auto_type, "Auto-Type");
    labels
}

fn add_binary(binaries: &mut Vec<Binary>, data: &[u8]) -> usize {
    match binaries.iter().position(|b| b.data == data) {
        Some(index) => index,
        None => {
            binaries.push(Binary {
                flags: 0,
                data: data.to_vec(),
            });
            binaries.len() - 1
        }
    }
}

/// Writes the properties that differ between `old` (the entry's current state) and `new`.
/// The edit must have passed [`KdbxDocument::validate_entry_edit`].
fn write_entry(entry: &mut Element, binaries: &mut Vec<Binary>, old: &EntryEdit, new: &EntryEdit) {
    let strings_changed = old.strings.len() != new.strings.len()
        || new
            .strings
            .iter()
            .any(|f| old.strings.iter().find(|o| o.key == f.key) != Some(f));
    if strings_changed {
        let existing: Vec<Element> = entry.children_named("String").cloned().collect();
        entry.remove_children("String");
        for field in &new.strings {
            // Reuse the existing element so unknown attributes survive.
            let mut element = existing
                .iter()
                .find(|s| s.child_text("Key") == Some(field.key.as_str()))
                .cloned()
                .unwrap_or_else(|| {
                    Element::with_children(
                        "String",
                        vec![Element::with_text("Key", field.key.clone())],
                    )
                });
            let value = element.ensure_child("Value", KEY_VALUE_ORDER);
            value.text = field.value.clone();
            if field.protected {
                value.set_attr("Protected", "True");
            } else {
                value.remove_attr("Protected");
            }
            entry.insert_ordered(element, ENTRY_ORDER);
        }
    }

    if old.tags != new.tags {
        entry.set_child_text("Tags", &format_tags(&new.tags), ENTRY_ORDER);
    }
    if old.icon_id != new.icon_id || old.custom_icon != new.custom_icon {
        write_icon(entry, new.icon_id, new.custom_icon, ENTRY_ORDER);
    }
    if old.foreground_color != new.foreground_color || old.background_color != new.background_color
    {
        entry.set_child_text("ForegroundColor", &new.foreground_color, ENTRY_ORDER);
        entry.set_child_text("BackgroundColor", &new.background_color, ENTRY_ORDER);
    }
    if old.override_url != new.override_url {
        entry.set_child_text("OverrideURL", &new.override_url, ENTRY_ORDER);
    }
    if expiry_changed(
        (old.expires, old.expiry_time),
        (new.expires, new.expiry_time),
    ) {
        write_expiry(entry, new.expires, new.expiry_time);
    }

    if old.attachments != new.attachments {
        let existing: Vec<Element> = entry.children_named("Binary").cloned().collect();
        entry.remove_children("Binary");
        for attachment in &new.attachments {
            let mut element = match &attachment.data {
                AttachmentData::Existing(current) => existing
                    .iter()
                    .find(|b| b.child_text("Key") == Some(current.as_str()))
                    .cloned()
                    .expect("validated attachment name"),
                AttachmentData::New(data) => {
                    let mut value = Element::new("Value");
                    value.set_attr("Ref", &add_binary(binaries, data).to_string());
                    Element::with_children("Binary", vec![Element::new("Key"), value])
                }
            };
            element.set_child_text("Key", &attachment.name, KEY_VALUE_ORDER);
            entry.insert_ordered(element, ENTRY_ORDER);
        }
    }

    if old.auto_type != new.auto_type {
        let auto_type = entry.ensure_child("AutoType", ENTRY_ORDER);
        let edit = &new.auto_type;
        auto_type.set_child_text("Enabled", format_bool(edit.enabled), AUTO_TYPE_ORDER);
        auto_type.set_child_text(
            "DataTransferObfuscation",
            &edit.obfuscation.to_string(),
            AUTO_TYPE_ORDER,
        );
        if !edit.default_sequence.is_empty() || auto_type.child("DefaultSequence").is_some() {
            auto_type.set_child_text("DefaultSequence", &edit.default_sequence, AUTO_TYPE_ORDER);
        }
        auto_type.remove_children("Association");
        for association in &edit.associations {
            auto_type.insert_ordered(
                Element::with_children(
                    "Association",
                    vec![
                        Element::with_text("Window", association.window.clone()),
                        Element::with_text("KeystrokeSequence", association.sequence.clone()),
                    ],
                ),
                AUTO_TYPE_ORDER,
            );
        }
    }
}

fn write_icon(element: &mut Element, icon_id: u32, custom_icon: Option<Uuid>, order: &[&str]) {
    element.set_child_text("IconID", &icon_id.to_string(), order);
    match custom_icon {
        Some(uuid) => element.set_child_text("CustomIconUUID", &format_uuid(uuid), order),
        None => element.remove_children("CustomIconUUID"),
    }
}

fn write_expiry(element: &mut Element, expires: bool, expiry_time: Option<DateTime<Utc>>) {
    let order = order_of(element);
    let times = element.ensure_child("Times", order);
    times.set_child_text("Expires", format_bool(expires), TIMES_ORDER);
    if let Some(time) = expiry_time {
        times.set_child_text("ExpiryTime", &format_time(time), TIMES_ORDER);
    }
}

fn group_edit_of(group: &Element) -> GroupEdit {
    let (icon_id, custom_icon) = icon_of(group);
    let (expires, expiry_time) = expiry_of(group);
    GroupEdit {
        name: group.child_text("Name").unwrap_or_default().to_string(),
        notes: group.child_text("Notes").unwrap_or_default().to_string(),
        icon_id,
        custom_icon,
        expires,
        expiry_time,
    }
}

/// Writes the differing group properties and returns their labels.
fn write_group(group: &mut Element, old: &GroupEdit, new: &GroupEdit) -> Vec<&'static str> {
    let mut labels = Vec::new();
    if old.name != new.name {
        group.set_child_text("Name", &new.name, GROUP_ORDER);
        labels.push("Name");
    }
    if old.notes != new.notes {
        group.set_child_text("Notes", &new.notes, GROUP_ORDER);
        labels.push("Notes");
    }
    if old.icon_id != new.icon_id || old.custom_icon != new.custom_icon {
        write_icon(group, new.icon_id, new.custom_icon, GROUP_ORDER);
        labels.push("Icon");
    }
    if expiry_changed(
        (old.expires, old.expiry_time),
        (new.expires, new.expiry_time),
    ) {
        write_expiry(group, new.expires, new.expiry_time);
        labels.push("Expiry");
    }
    labels
}

fn history_snapshot(entry: &Element) -> Element {
    let mut snapshot = entry.clone();
    snapshot.remove_children("History");
    snapshot
}

fn push_history(entry: &mut Element, snapshot: Element) {
    entry
        .ensure_child("History", ENTRY_ORDER)
        .children
        .push(snapshot);
}

/// Approximate entry size, computed like KeePass `PwEntry.GetSize` for history limits.
fn entry_size(entry: &Element, binaries: &[Binary]) -> u64 {
    let chars = |text: &str| text.chars().count() as u64;
    let mut size = 128;
    for field in strings_of(entry) {
        size += chars(&field.key) + chars(&field.value);
    }
    for (name, reference) in binary_refs_of(entry) {
        size += chars(&name)
            + reference
                .and_then(|r| binaries.get(r))
                .map_or(0, |b| b.data.len() as u64);
    }
    let auto_type = auto_type_of(entry);
    size += chars(&auto_type.default_sequence);
    for association in &auto_type.associations {
        size += chars(&association.window) + chars(&association.sequence);
    }
    size += chars(entry.child_text("OverrideURL").unwrap_or_default());
    for tag in parse_tags(entry.child_text("Tags").unwrap_or_default()) {
        size += chars(&tag);
    }
    if let Some(custom_data) = entry.child("CustomData") {
        for item in custom_data.children_named("Item") {
            size += chars(item.child_text("Key").unwrap_or_default())
                + chars(item.child_text("Value").unwrap_or_default());
        }
    }
    if let Some(history) = entry.child("History") {
        for version in history.children_named("Entry") {
            size += entry_size(version, binaries);
        }
    }
    size
}

/// Removes the oldest history versions until both limits hold (negative = unlimited).
pub(crate) fn maintain_history(
    entry: &mut Element,
    max_items: i32,
    max_size: i64,
    binaries: &[Binary],
) {
    let Some(history) = entry.child_mut("History") else {
        return;
    };
    let remove_oldest = |history: &mut Element| -> Option<Element> {
        let oldest = history
            .children
            .iter()
            .enumerate()
            .filter(|(_, c)| c.name == "Entry")
            .min_by_key(|(_, c)| time_of(c, "LastModificationTime"))
            .map(|(i, _)| i)?;
        Some(history.children.remove(oldest))
    };
    if let Ok(max_items) = usize::try_from(max_items) {
        while history.children_named("Entry").count() > max_items {
            if remove_oldest(history).is_none() {
                break;
            }
        }
    }
    if let Ok(max_size) = u64::try_from(max_size) {
        let mut total: u64 = history
            .children_named("Entry")
            .map(|v| entry_size(v, binaries))
            .sum();
        while total > max_size {
            match remove_oldest(history) {
                Some(removed) => total -= entry_size(&removed, binaries),
                None => break,
            }
        }
    }
}

fn for_each_entry_mut(group: &mut Element, visit: &mut dyn FnMut(&mut Element)) {
    for child in &mut group.children {
        match child.name.as_str() {
            "Entry" => visit(child),
            "Group" => for_each_entry_mut(child, visit),
            _ => {}
        }
    }
}

/// UUIDs of an entry, or of a group with everything below it; returns the entry count.
fn collect_uuids(element: &Element, uuids: &mut Vec<Uuid>) -> usize {
    if let Some(uuid) = uuid_of(element) {
        uuids.push(uuid);
    }
    match element.name.as_str() {
        "Entry" => 1,
        "Group" => element
            .children
            .iter()
            .filter(|c| c.name == "Entry" || c.name == "Group")
            .map(|c| collect_uuids(c, uuids))
            .sum(),
        _ => 0,
    }
}

impl KdbxDocument {
    /// Applies one edit. Errors leave the document unchanged.
    pub fn apply(&mut self, change: Change) -> Result<ChangeOutcome> {
        let now = now();
        match change {
            Change::CreateEntry { group, entry } => self.create_entry(group, &entry, now),
            Change::UpdateEntry { uuid, entry } => self.update_entry(uuid, &entry, now),
            Change::DuplicateEntry { uuid } => self.duplicate_entry(uuid, now),
            Change::MoveEntry { uuid, group } => self.move_entry(uuid, group, now),
            Change::DeleteEntry { uuid } => self.delete_entry(uuid, now),
            Change::RestoreHistory { uuid, index } => self.restore_history(uuid, index, now),
            Change::DeleteHistory { uuid, index } => self.delete_history(uuid, index),
            Change::CreateGroup { parent, group } => self.create_group(parent, &group, now),
            Change::UpdateGroup { uuid, group } => self.update_group(uuid, &group, now),
            Change::MoveGroup { uuid, parent } => self.move_group(uuid, parent, now),
            Change::DeleteGroup { uuid } => self.delete_group(uuid, now),
            Change::EmptyRecycleBin => self.empty_recycle_bin(now),
            Change::AddCustomIcon { png } => self.add_custom_icon(&png, now),
            Change::UpdateMeta { meta } => self.update_meta(&meta, now),
        }
    }

    fn has_custom_icon(&self, uuid: Uuid) -> bool {
        self.meta_element()
            .child("CustomIcons")
            .is_some_and(|icons| {
                icons
                    .children_named("Icon")
                    .any(|i| uuid_of(i) == Some(uuid))
            })
    }

    fn validate_entry_edit(&self, entry: Option<&Element>, edit: &EntryEdit) -> Result<()> {
        let mut keys = HashSet::new();
        for field in &edit.strings {
            if field.key.is_empty() {
                return Err(Error::InvalidEntry(
                    "Field names must not be empty".to_string(),
                ));
            }
            if !keys.insert(field.key.as_str()) {
                return Err(Error::InvalidEntry(format!(
                    "Duplicate field “{}”",
                    field.key
                )));
            }
        }
        let existing = entry.map(binary_refs_of).unwrap_or_default();
        let mut names = HashSet::new();
        for attachment in &edit.attachments {
            if attachment.name.is_empty() {
                return Err(Error::InvalidEntry(
                    "Attachment names must not be empty".to_string(),
                ));
            }
            if !names.insert(attachment.name.as_str()) {
                return Err(Error::InvalidEntry(format!(
                    "Duplicate attachment “{}”",
                    attachment.name
                )));
            }
            if let AttachmentData::Existing(current) = &attachment.data {
                if !existing.iter().any(|(name, _)| name == current) {
                    return Err(Error::InvalidEntry(format!(
                        "Attachment “{current}” does not exist"
                    )));
                }
            }
        }
        if let Some(icon) = edit.custom_icon {
            if !self.has_custom_icon(icon) {
                return Err(Error::InvalidEntry(format!(
                    "Custom icon {icon} does not exist"
                )));
            }
        }
        Ok(())
    }

    fn recycle_bin_enabled(&self) -> bool {
        self.meta_element()
            .child_text("RecycleBinEnabled")
            .and_then(parse_bool)
            .unwrap_or(true)
    }

    /// Returns the recycle bin, creating it under the root group when missing.
    fn ensure_recycle_bin(&mut self, now: DateTime<Utc>) -> Result<Uuid> {
        if let Some(bin) = self.recycle_bin_uuid() {
            if self.find(bin, Kind::Group).is_some() {
                return Ok(bin);
            }
        }
        let uuid = Uuid::new_v4();
        let mut group = new_group_element(uuid, now);
        group.set_child_text("Name", "Recycle Bin", GROUP_ORDER);
        group.set_child_text("IconID", &ICON_RECYCLE_BIN.to_string(), GROUP_ORDER);
        group.set_child_text("IsExpanded", "False", GROUP_ORDER);
        group.set_child_text("EnableAutoType", "False", GROUP_ORDER);
        group.set_child_text("EnableSearching", "False", GROUP_ORDER);
        let root = self.root_group_path()?;
        element_at_mut(&mut self.xml, &root).insert_ordered(group, GROUP_ORDER);
        let meta = self.meta_element_mut();
        meta.set_child_text("RecycleBinUUID", &format_uuid(uuid), META_ORDER);
        meta.set_child_text("RecycleBinChanged", &format_time(now), META_ORDER);
        Ok(uuid)
    }

    fn record_deletions(&mut self, uuids: &[Uuid], now: DateTime<Utc>) -> Result<()> {
        let root = self.root_path()?;
        let deleted = self.xml.children[root].ensure_child("DeletedObjects", ROOT_ORDER);
        let time = format_time(now);
        for uuid in uuids {
            deleted.children.retain(|d| uuid_of(d) != Some(*uuid));
            deleted.children.push(Element::with_children(
                "DeletedObject",
                vec![
                    Element::with_text("UUID", format_uuid(*uuid)),
                    Element::with_text("DeletionTime", time.clone()),
                ],
            ));
        }
        Ok(())
    }

    /// Moves the entry or group at `path` into group `target`, recording the move time.
    fn relocate(&mut self, path: &[usize], target: Uuid, now: DateTime<Utc>) -> Result<()> {
        let (index, parent_path) = path
            .split_last()
            .ok_or_else(|| Error::InvalidGroup("Cannot move the document root".to_string()))?;
        let old_parent = uuid_of(element_at(&self.xml, parent_path));
        let mut element = element_at_mut(&mut self.xml, parent_path)
            .children
            .remove(*index);
        let Some(target_path) = self.find(target, Kind::Group) else {
            element_at_mut(&mut self.xml, parent_path)
                .children
                .insert(*index, element);
            return Err(Error::GroupNotFound(target));
        };
        set_times(&mut element, &["LocationChanged"], now);
        // PreviousParentGroup exists since KDBX 4.1.
        if self.header.minor >= 1 {
            if let Some(parent) = old_parent {
                let order = order_of(&element);
                element.set_child_text("PreviousParentGroup", &format_uuid(parent), order);
            }
        }
        element_at_mut(&mut self.xml, &target_path).insert_ordered(element, GROUP_ORDER);
        Ok(())
    }

    fn create_entry(
        &mut self,
        group: Uuid,
        edit: &EntryEdit,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let group_path = self.group_path(group)?;
        self.validate_entry_edit(None, edit)?;
        let uuid = Uuid::new_v4();
        let mut entry = new_entry_element(uuid, now);
        let blank = entry_edit_of(&entry);
        write_entry(&mut entry, &mut self.binaries, &blank, edit);
        let title = entry_title(&entry);
        let parent = element_at_mut(&mut self.xml, &group_path);
        let group_label = group_name(parent);
        parent.insert_ordered(entry, GROUP_ORDER);
        Ok(changed(
            format!("Created entry “{title}” in “{group_label}”"),
            Some(uuid),
        ))
    }

    fn update_entry(
        &mut self,
        uuid: Uuid,
        edit: &EntryEdit,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let entry = element_at(&self.xml, &path);
        self.validate_entry_edit(Some(entry), edit)?;
        let old = entry_edit_of(entry);
        // Editors send every standard field. An empty value for a field the entry
        // never stored is not a change, so do not write or report it.
        let mut edit = edit.clone();
        edit.strings
            .retain(|f| !f.value.is_empty() || old.strings.iter().any(|o| o.key == f.key));
        let edit = &edit;
        let labels = entry_changes(&old, edit);
        if labels.is_empty() {
            return Ok(unchanged(format!(
                "No changes to entry “{}”",
                entry_title(entry)
            )));
        }
        let snapshot = history_snapshot(entry);
        let (max_items, max_size) = self.history_limits();
        let entry = element_at_mut(&mut self.xml, &path);
        write_entry(entry, &mut self.binaries, &old, edit);
        touch_modified(entry, now);
        push_history(entry, snapshot);
        maintain_history(entry, max_items, max_size, &self.binaries);
        Ok(changed(
            format!(
                "Edited entry “{}”: {}",
                entry_title(entry),
                labels.join(", ")
            ),
            None,
        ))
    }

    fn duplicate_entry(&mut self, uuid: Uuid, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let mut copy = element_at(&self.xml, &path).clone();
        let title = entry_title(&copy);
        let new_uuid = Uuid::new_v4();
        copy.set_child_text("UUID", &format_uuid(new_uuid), ENTRY_ORDER);
        if let Some(value) = copy
            .children
            .iter_mut()
            .find(|s| s.name == "String" && s.child_text("Key") == Some("Title"))
            .and_then(|s| s.child_mut("Value"))
        {
            value.text.push_str(" - Copy");
        }
        copy.remove_children("History");
        copy.remove_children("PreviousParentGroup");
        copy.insert_ordered(Element::new("History"), ENTRY_ORDER);
        set_times(
            &mut copy,
            &[
                "CreationTime",
                "LastModificationTime",
                "LastAccessTime",
                "LocationChanged",
            ],
            now,
        );
        copy.ensure_child("Times", ENTRY_ORDER)
            .set_child_text("UsageCount", "0", TIMES_ORDER);
        let (index, parent_path) = path.split_last().expect("entry paths are never empty");
        element_at_mut(&mut self.xml, parent_path)
            .children
            .insert(index + 1, copy);
        Ok(changed(
            format!("Duplicated entry “{title}”"),
            Some(new_uuid),
        ))
    }

    fn move_entry(&mut self, uuid: Uuid, group: Uuid, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let target = self.group_path(group)?;
        let title = entry_title(element_at(&self.xml, &path));
        let target_name = group_name(element_at(&self.xml, &target));
        if uuid_of(element_at(&self.xml, &path[..path.len() - 1])) == Some(group) {
            return Ok(unchanged(format!(
                "Entry “{title}” is already in “{target_name}”"
            )));
        }
        self.relocate(&path, group, now)?;
        Ok(changed(
            format!("Moved entry “{title}” to “{target_name}”"),
            None,
        ))
    }

    fn delete_entry(&mut self, uuid: Uuid, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let title = entry_title(element_at(&self.xml, &path));
        if self.recycle_bin_enabled() && !self.path_in_recycle_bin(&path) {
            let bin = self.ensure_recycle_bin(now)?;
            let path = self.entry_path(uuid)?;
            self.relocate(&path, bin, now)?;
            return Ok(changed(
                format!("Moved entry “{title}” to the recycle bin"),
                None,
            ));
        }
        let (index, parent_path) = path.split_last().expect("entry paths are never empty");
        element_at_mut(&mut self.xml, parent_path)
            .children
            .remove(*index);
        self.record_deletions(&[uuid], now)?;
        Ok(changed(
            format!("Permanently deleted entry “{title}”"),
            None,
        ))
    }

    fn history_index(entry: &Element, index: usize) -> Result<usize> {
        entry
            .child("History")
            .and_then(|h| {
                h.children
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.name == "Entry")
                    .nth(index)
            })
            .map(|(i, _)| i)
            .ok_or_else(|| Error::InvalidEntry(format!("History version {index} does not exist")))
    }

    fn restore_history(
        &mut self,
        uuid: Uuid,
        index: usize,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let current = element_at(&self.xml, &path);
        let position = Self::history_index(current, index)?;
        let history = current
            .child("History")
            .expect("history_index found it")
            .clone();
        let mut restored = history.children[position].clone();
        let snapshot = history_snapshot(current);

        // Identity, location and the history itself belong to the entry, not the version.
        restored.set_child_text("UUID", &format_uuid(uuid), ENTRY_ORDER);
        restored.remove_children("History");
        restored.insert_ordered(history, ENTRY_ORDER);
        match current.child("PreviousParentGroup") {
            Some(previous) => restored.replace_child(previous.clone(), ENTRY_ORDER),
            None => restored.remove_children("PreviousParentGroup"),
        }
        if let Some(times) = current.child("Times") {
            let restored_times = restored.ensure_child("Times", ENTRY_ORDER);
            for name in ["LocationChanged", "UsageCount"] {
                if let Some(value) = times.child(name) {
                    restored_times.replace_child(value.clone(), TIMES_ORDER);
                }
            }
        }

        let (max_items, max_size) = self.history_limits();
        touch_modified(&mut restored, now);
        push_history(&mut restored, snapshot);
        maintain_history(&mut restored, max_items, max_size, &self.binaries);
        let title = entry_title(&restored);
        *element_at_mut(&mut self.xml, &path) = restored;
        Ok(changed(
            format!("Restored entry “{title}” from history"),
            None,
        ))
    }

    fn delete_history(&mut self, uuid: Uuid, index: usize) -> Result<ChangeOutcome> {
        let path = self.entry_path(uuid)?;
        let entry = element_at_mut(&mut self.xml, &path);
        let position = Self::history_index(entry, index)?;
        entry
            .child_mut("History")
            .expect("history_index found it")
            .children
            .remove(position);
        Ok(changed(
            format!(
                "Deleted a history version of entry “{}”",
                entry_title(entry)
            ),
            None,
        ))
    }

    fn create_group(
        &mut self,
        parent: Uuid,
        edit: &GroupEdit,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let parent_path = self.group_path(parent)?;
        if let Some(icon) = edit.custom_icon.filter(|i| !self.has_custom_icon(*i)) {
            return Err(Error::InvalidGroup(format!(
                "Custom icon {icon} does not exist"
            )));
        }
        let uuid = Uuid::new_v4();
        let mut group = new_group_element(uuid, now);
        let blank = group_edit_of(&group);
        write_group(&mut group, &blank, edit);
        let name = group_name(&group);
        let parent = element_at_mut(&mut self.xml, &parent_path);
        let parent_name = group_name(parent);
        parent.insert_ordered(group, GROUP_ORDER);
        Ok(changed(
            format!("Created group “{name}” in “{parent_name}”"),
            Some(uuid),
        ))
    }

    fn update_group(
        &mut self,
        uuid: Uuid,
        edit: &GroupEdit,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let path = self.group_path(uuid)?;
        if let Some(icon) = edit.custom_icon.filter(|i| !self.has_custom_icon(*i)) {
            return Err(Error::InvalidGroup(format!(
                "Custom icon {icon} does not exist"
            )));
        }
        let group = element_at_mut(&mut self.xml, &path);
        let old = group_edit_of(group);
        let labels = write_group(group, &old, edit);
        if labels.is_empty() {
            return Ok(unchanged(format!(
                "No changes to group “{}”",
                group_name(group)
            )));
        }
        touch_modified(group, now);
        Ok(changed(
            format!(
                "Edited group “{}”: {}",
                group_name(group),
                labels.join(", ")
            ),
            None,
        ))
    }

    fn move_group(
        &mut self,
        uuid: Uuid,
        parent: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ChangeOutcome> {
        let path = self.group_path(uuid)?;
        if path == self.root_group_path()? {
            return Err(Error::InvalidGroup(
                "The root group cannot be moved".to_string(),
            ));
        }
        let target = self.group_path(parent)?;
        if target.starts_with(&path) {
            return Err(Error::InvalidGroup(
                "A group cannot be moved into itself or one of its subgroups".to_string(),
            ));
        }
        let name = group_name(element_at(&self.xml, &path));
        let target_name = group_name(element_at(&self.xml, &target));
        if uuid_of(element_at(&self.xml, &path[..path.len() - 1])) == Some(parent) {
            return Ok(unchanged(format!(
                "Group “{name}” is already in “{target_name}”"
            )));
        }
        self.relocate(&path, parent, now)?;
        Ok(changed(
            format!("Moved group “{name}” to “{target_name}”"),
            None,
        ))
    }

    fn delete_group(&mut self, uuid: Uuid, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let path = self.group_path(uuid)?;
        if path == self.root_group_path()? {
            return Err(Error::InvalidGroup(
                "The root group cannot be deleted".to_string(),
            ));
        }
        let name = group_name(element_at(&self.xml, &path));
        // Same rules as KeePass: the bin itself, groups inside it and groups containing
        // it are deleted permanently.
        let bin_path = self
            .recycle_bin_uuid()
            .and_then(|bin| self.find(bin, Kind::Group));
        let permanent = !self.recycle_bin_enabled()
            || self.path_in_recycle_bin(&path)
            || bin_path.is_some_and(|bin| bin.starts_with(&path));
        if !permanent {
            let bin = self.ensure_recycle_bin(now)?;
            let path = self.group_path(uuid)?;
            self.relocate(&path, bin, now)?;
            return Ok(changed(
                format!("Moved group “{name}” to the recycle bin"),
                None,
            ));
        }
        let (index, parent_path) = path.split_last().expect("group paths are never empty");
        let group = element_at_mut(&mut self.xml, parent_path)
            .children
            .remove(*index);
        let mut uuids = Vec::new();
        collect_uuids(&group, &mut uuids);
        self.record_deletions(&uuids, now)?;
        Ok(changed(format!("Permanently deleted group “{name}”"), None))
    }

    fn empty_recycle_bin(&mut self, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let Some(path) = self
            .recycle_bin_uuid()
            .and_then(|bin| self.find(bin, Kind::Group))
        else {
            return Ok(unchanged("The recycle bin is empty".to_string()));
        };
        let bin = element_at_mut(&mut self.xml, &path);
        let (removed, kept): (Vec<Element>, Vec<Element>) = std::mem::take(&mut bin.children)
            .into_iter()
            .partition(|c| c.name == "Entry" || c.name == "Group");
        bin.children = kept;
        if removed.is_empty() {
            return Ok(unchanged("The recycle bin is empty".to_string()));
        }
        let mut uuids = Vec::new();
        let entries: usize = removed.iter().map(|c| collect_uuids(c, &mut uuids)).sum();
        let groups = uuids.len() - entries;
        self.record_deletions(&uuids, now)?;
        Ok(changed(
            format!("Emptied the recycle bin ({entries} entries, {groups} groups)"),
            None,
        ))
    }

    fn add_custom_icon(&mut self, png: &[u8], now: DateTime<Utc>) -> Result<ChangeOutcome> {
        if png.is_empty() {
            return Err(Error::InvalidEntry("Custom icon data is empty".to_string()));
        }
        if let Some(existing) = self.custom_icons().into_iter().find(|i| i.png == png) {
            return Ok(ChangeOutcome {
                summary: "Custom icon already exists".to_string(),
                created: Some(existing.uuid),
                changed: false,
            });
        }
        let uuid = Uuid::new_v4();
        let mut icon = Element::with_children(
            "Icon",
            vec![
                Element::with_text("UUID", format_uuid(uuid)),
                Element::with_text("Data", STANDARD.encode(png)),
            ],
        );
        // Icon timestamps exist since KDBX 4.1.
        if self.header.minor >= 1 {
            icon.children
                .push(Element::with_text("LastModificationTime", format_time(now)));
        }
        self.meta_element_mut()
            .ensure_child("CustomIcons", META_ORDER)
            .children
            .push(icon);
        Ok(changed("Added a custom icon".to_string(), Some(uuid)))
    }

    fn update_meta(&mut self, edit: &MetaEdit, now: DateTime<Utc>) -> Result<ChangeOutcome> {
        let current = self.meta();
        let time = format_time(now);
        let mut labels = Vec::new();
        let meta = self.meta_element_mut();
        if current.name != edit.name {
            meta.set_child_text("DatabaseName", &edit.name, META_ORDER);
            meta.set_child_text("DatabaseNameChanged", &time, META_ORDER);
            labels.push("Name");
        }
        if current.description != edit.description {
            meta.set_child_text("DatabaseDescription", &edit.description, META_ORDER);
            meta.set_child_text("DatabaseDescriptionChanged", &time, META_ORDER);
            labels.push("Description");
        }
        if current.recycle_bin_enabled != edit.recycle_bin_enabled {
            meta.set_child_text(
                "RecycleBinEnabled",
                format_bool(edit.recycle_bin_enabled),
                META_ORDER,
            );
            meta.set_child_text("RecycleBinChanged", &time, META_ORDER);
            labels.push("Recycle bin");
        }
        let limits_changed = current.history_max_items != edit.history_max_items
            || current.history_max_size != edit.history_max_size;
        if limits_changed {
            meta.set_child_text(
                "HistoryMaxItems",
                &edit.history_max_items.to_string(),
                META_ORDER,
            );
            meta.set_child_text(
                "HistoryMaxSize",
                &edit.history_max_size.to_string(),
                META_ORDER,
            );
            meta.set_child_text("SettingsChanged", &time, META_ORDER);
            labels.push("History limits");
        }
        if labels.is_empty() {
            return Ok(unchanged("No changes to database settings".to_string()));
        }
        if limits_changed {
            let root = self.root_group_path()?;
            let binaries = &self.binaries;
            for_each_entry_mut(element_at_mut(&mut self.xml, &root), &mut |entry| {
                maintain_history(
                    entry,
                    edit.history_max_items,
                    edit.history_max_size,
                    binaries,
                );
            });
        }
        Ok(changed(
            format!("Changed database settings: {}", labels.join(", ")),
            None,
        ))
    }
}
