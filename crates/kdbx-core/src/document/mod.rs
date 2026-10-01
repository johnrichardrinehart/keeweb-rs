//! Full-fidelity KDBX 4 document with editing, saving and three-way merge.
//!
//! The inner XML is kept as a generic element tree, so elements and attributes this
//! module does not interpret survive a save in place. Protected values are held as
//! plaintext in the tree and re-encrypted with a fresh inner stream on save.
//! Attachment contents live in the inner header binary pool and are referenced from
//! entries by pool index (`<Binary><Value Ref="n"/></Binary>`).

mod container;
mod edit;
mod merge;
#[cfg(test)]
mod tests;
mod types;
mod values;
mod xml;

pub use merge::merge;
pub use types::{
    AttachmentData, AttachmentEdit, AttachmentView, AutoTypeAssociation, AutoTypeEdit, Change,
    ChangeOutcome, CustomIconView, EntryEdit, EntryView, GroupEdit, GroupView, MergeOutcome,
    MetaEdit, MetaView, StringField, TimesView,
};

use crate::error::{Error, Result};
use crate::kdbx4_decrypt::{KdfParams, ProtectedStreamCipher, parse_kdbx4_header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use container::{Binary, OuterHeader, STREAM_CHACHA20};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use values::{parse_bool, parse_tags, parse_time, parse_uuid, random_bytes};
use xml::Element;

/// KeePass defaults used when Meta lacks the history limits.
const DEFAULT_HISTORY_MAX_ITEMS: i32 = 10;
const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;

#[derive(Clone)]
pub struct KdbxDocument {
    header: OuterHeader,
    binaries: Vec<Binary>,
    xml: Element,
}

impl std::fmt::Debug for KdbxDocument {
    // Field values are secrets; only report the shape.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdbxDocument")
            .field("version", &format_args!("4.{}", self.header.minor))
            .field("binaries", &self.binaries.len())
            .finish_non_exhaustive()
    }
}

/// Deduplicating builder for an inner header binary pool.
#[derive(Default)]
pub(crate) struct BinaryPool {
    binaries: Vec<Binary>,
    index: HashMap<[u8; 32], usize>,
}

impl BinaryPool {
    fn add(&mut self, binary: &Binary) -> usize {
        let digest: [u8; 32] = Sha256::digest(&binary.data).into();
        *self.index.entry(digest).or_insert_with(|| {
            self.binaries.push(binary.clone());
            self.binaries.len() - 1
        })
    }

    fn into_binaries(self) -> Vec<Binary> {
        self.binaries
    }
}

/// Rewrites every attachment reference (`Binary/Value[@Ref]`) below `element`.
pub(crate) fn remap_binary_refs(
    element: &mut Element,
    map: &mut dyn FnMut(usize) -> Result<usize>,
) -> Result<()> {
    if element.name == "Binary" {
        if let Some(value) = element.child_mut("Value") {
            if let Some(reference) = value.attr("Ref") {
                let old = reference.trim().parse::<usize>().map_err(|_| {
                    Error::ParseError(format!("Invalid attachment reference {reference:?}"))
                })?;
                value.set_attr("Ref", &map(old)?.to_string());
            }
        }
    }
    for child in &mut element.children {
        remap_binary_refs(child, map)?;
    }
    Ok(())
}

/// Copies the binaries referenced below `element` from `source` into `pool`, updating refs.
pub(crate) fn import_binaries(
    element: &mut Element,
    source: &[Binary],
    pool: &mut BinaryPool,
) -> Result<()> {
    remap_binary_refs(element, &mut |old| {
        source
            .get(old)
            .map(|binary| pool.add(binary))
            .ok_or_else(|| {
                Error::ParseError(format!(
                    "Attachment reference {old} points to a missing binary"
                ))
            })
    })
}

pub(crate) fn element_at<'a>(root: &'a Element, path: &[usize]) -> &'a Element {
    path.iter().fold(root, |element, &i| &element.children[i])
}

pub(crate) fn element_at_mut<'a>(root: &'a mut Element, path: &[usize]) -> &'a mut Element {
    let mut element = root;
    for &i in path {
        element = &mut element.children[i];
    }
    element
}

pub(crate) fn uuid_of(element: &Element) -> Option<Uuid> {
    element.child_text("UUID").and_then(parse_uuid)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Entry,
    Group,
}

fn find_in_group(group: &Element, path: &mut Vec<usize>, uuid: Uuid, kind: Kind) -> bool {
    for (i, child) in group.children.iter().enumerate() {
        let hit = match child.name.as_str() {
            "Entry" => kind == Kind::Entry && uuid_of(child) == Some(uuid),
            "Group" => {
                path.push(i);
                if kind == Kind::Group && uuid_of(child) == Some(uuid)
                    || find_in_group(child, path, uuid, kind)
                {
                    return true;
                }
                path.pop();
                false
            }
            _ => false,
        };
        if hit {
            path.push(i);
            return true;
        }
    }
    false
}

fn string_value<'a>(entry: &'a Element, key: &str) -> Option<&'a str> {
    entry
        .children_named("String")
        .find(|s| s.child_text("Key") == Some(key))
        .and_then(|s| s.child_text("Value"))
}

pub(crate) fn entry_title(entry: &Element) -> String {
    match string_value(entry, "Title") {
        Some(title) if !title.is_empty() => title.to_string(),
        _ => "(untitled)".to_string(),
    }
}

pub(crate) fn group_name(group: &Element) -> String {
    match group.child_text("Name") {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => "(unnamed)".to_string(),
    }
}

pub(crate) fn time_of(element: &Element, name: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    element
        .child("Times")
        .and_then(|t| t.child_text(name))
        .and_then(parse_time)
}

fn times_view(element: &Element) -> TimesView {
    let times = element.child("Times");
    let time = |name: &str| times.and_then(|t| t.child_text(name)).and_then(parse_time);
    TimesView {
        creation: time("CreationTime"),
        last_modification: time("LastModificationTime"),
        last_access: time("LastAccessTime"),
        location_changed: time("LocationChanged"),
        usage_count: times
            .and_then(|t| t.child_text("UsageCount"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    }
}

fn expiry_of(element: &Element) -> (bool, Option<chrono::DateTime<chrono::Utc>>) {
    let times = element.child("Times");
    (
        times
            .and_then(|t| t.child_text("Expires"))
            .and_then(parse_bool)
            .unwrap_or(false),
        times
            .and_then(|t| t.child_text("ExpiryTime"))
            .and_then(parse_time),
    )
}

fn icon_of(element: &Element) -> (u32, Option<Uuid>) {
    (
        element
            .child_text("IconID")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        element
            .child_text("CustomIconUUID")
            .and_then(parse_uuid)
            .filter(|u| !u.is_nil()),
    )
}

pub(crate) fn auto_type_of(entry: &Element) -> AutoTypeEdit {
    let Some(auto_type) = entry.child("AutoType") else {
        return AutoTypeEdit::default();
    };
    AutoTypeEdit {
        enabled: auto_type
            .child_text("Enabled")
            .and_then(parse_bool)
            .unwrap_or(true),
        obfuscation: auto_type
            .child_text("DataTransferObfuscation")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
        default_sequence: auto_type
            .child_text("DefaultSequence")
            .unwrap_or_default()
            .to_string(),
        associations: auto_type
            .children_named("Association")
            .map(|a| AutoTypeAssociation {
                window: a.child_text("Window").unwrap_or_default().to_string(),
                sequence: a
                    .child_text("KeystrokeSequence")
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect(),
    }
}

pub(crate) fn strings_of(entry: &Element) -> Vec<StringField> {
    entry
        .children_named("String")
        .map(|s| {
            let value = s.child("Value");
            StringField {
                key: s.child_text("Key").unwrap_or_default().to_string(),
                value: value.map(|v| v.text.clone()).unwrap_or_default(),
                protected: value.is_some_and(Element::is_protected),
            }
        })
        .collect()
}

/// Attachment name and inner header pool index.
pub(crate) fn binary_refs_of(entry: &Element) -> Vec<(String, Option<usize>)> {
    entry
        .children_named("Binary")
        .map(|b| {
            (
                b.child_text("Key").unwrap_or_default().to_string(),
                b.child("Value")
                    .and_then(|v| v.attr("Ref"))
                    .and_then(|r| r.trim().parse().ok()),
            )
        })
        .collect()
}

impl KdbxDocument {
    /// Reads the KDF parameters from the outer header without decrypting anything.
    pub fn kdf_request(data: &[u8]) -> Result<KdfParams> {
        Ok(parse_kdbx4_header(data)?.kdf_params)
    }

    /// Opens a KDBX 4 file with the KDF output (`transformed_key`) computed by the caller.
    /// `composite_key` is the KDF input; it is not needed while the KDF parameters stay
    /// unchanged, which is always the case for files written by [`KdbxDocument::save`].
    pub fn open(data: &[u8], composite_key: &[u8; 32], transformed_key: &[u8; 32]) -> Result<Self> {
        let _ = composite_key;
        let decrypted = container::decrypt(data, transformed_key)?;
        if decrypted.stream_id != STREAM_CHACHA20 {
            return Err(Error::UnsupportedFormat(format!(
                "inner random stream {} is not supported; only ChaCha20 is",
                decrypted.stream_id
            )));
        }
        let mut stream = ProtectedStreamCipher::new(&decrypted.stream_key)?;
        let xml = xml::parse(&decrypted.xml, |encoded| stream.decrypt(encoded))?;
        let document = Self {
            header: decrypted.header,
            binaries: decrypted.binaries,
            xml,
        };
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<()> {
        if self.xml.name != "KeePassFile" {
            return Err(Error::ParseError("XML root is not KeePassFile".to_string()));
        }
        if self.xml.child("Meta").is_none() {
            return Err(Error::ParseError("Missing Meta element".to_string()));
        }
        let root_group = self.root_group_path()?;
        if uuid_of(element_at(&self.xml, &root_group)).is_none() {
            return Err(Error::ParseError("Root group has no UUID".to_string()));
        }
        Ok(())
    }

    /// Writes the document as KDBX 4 with the same version, cipher, compression and KDF
    /// parameters, and a fresh master seed, encryption IV and inner stream key.
    /// Only referenced binaries are written; references are renumbered accordingly.
    pub fn save(&self, composite_key: &[u8; 32], transformed_key: &[u8; 32]) -> Result<Vec<u8>> {
        let _ = composite_key;
        let mut tree = self.xml.clone();
        let mut pool = BinaryPool::default();
        import_binaries(&mut tree, &self.binaries, &mut pool)
            .map_err(|e| Error::SaveError(e.to_string()))?;
        let stream_key = random_bytes(64)?;
        let mut stream = ProtectedStreamCipher::new(&stream_key)?;
        let xml = xml::write(&tree, |plain| stream.encrypt(plain));
        container::encrypt(
            &self.header,
            transformed_key,
            &stream_key,
            &pool.into_binaries(),
            &xml,
        )
    }

    pub(crate) fn root_path(&self) -> Result<usize> {
        self.xml
            .children
            .iter()
            .position(|c| c.name == "Root")
            .ok_or_else(|| Error::ParseError("Missing Root element".to_string()))
    }

    pub(crate) fn root_group_path(&self) -> Result<Vec<usize>> {
        let root = self.root_path()?;
        let group = self.xml.children[root]
            .children
            .iter()
            .position(|c| c.name == "Group")
            .ok_or_else(|| Error::ParseError("Missing root group".to_string()))?;
        Ok(vec![root, group])
    }

    pub(crate) fn root_group(&self) -> &Element {
        let path = self
            .root_group_path()
            .expect("validated when the document was opened");
        element_at(&self.xml, &path)
    }

    pub(crate) fn meta_element(&self) -> &Element {
        self.xml
            .child("Meta")
            .expect("validated when the document was opened")
    }

    pub(crate) fn meta_element_mut(&mut self) -> &mut Element {
        self.xml
            .child_mut("Meta")
            .expect("validated when the document was opened")
    }

    pub(crate) fn find(&self, uuid: Uuid, kind: Kind) -> Option<Vec<usize>> {
        let mut path = self.root_group_path().ok()?;
        let root = element_at(&self.xml, &path);
        if kind == Kind::Group && uuid_of(root) == Some(uuid) {
            return Some(path);
        }
        find_in_group(root, &mut path, uuid, kind).then_some(path)
    }

    pub(crate) fn entry_path(&self, uuid: Uuid) -> Result<Vec<usize>> {
        self.find(uuid, Kind::Entry)
            .ok_or(Error::EntryNotFound(uuid))
    }

    pub(crate) fn group_path(&self, uuid: Uuid) -> Result<Vec<usize>> {
        self.find(uuid, Kind::Group)
            .ok_or(Error::GroupNotFound(uuid))
    }

    /// The recycle bin group UUID when the bin is enabled.
    pub(crate) fn recycle_bin_uuid(&self) -> Option<Uuid> {
        let meta = self.meta_element();
        let enabled = meta
            .child_text("RecycleBinEnabled")
            .and_then(parse_bool)
            .unwrap_or(true);
        if !enabled {
            return None;
        }
        meta.child_text("RecycleBinUUID")
            .and_then(parse_uuid)
            .filter(|u| !u.is_nil())
    }

    /// Whether any group on `path` (a path to an entry or group) is the recycle bin.
    pub(crate) fn path_in_recycle_bin(&self, path: &[usize]) -> bool {
        let Some(bin) = self.recycle_bin_uuid() else {
            return false;
        };
        let start = self.root_group_path().map(|p| p.len()).unwrap_or(2);
        (start..=path.len()).any(|len| {
            let element = element_at(&self.xml, &path[..len]);
            element.name == "Group" && uuid_of(element) == Some(bin)
        })
    }

    pub(crate) fn history_limits(&self) -> (i32, i64) {
        let meta = self.meta_element();
        (
            meta.child_text("HistoryMaxItems")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(DEFAULT_HISTORY_MAX_ITEMS),
            meta.child_text("HistoryMaxSize")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(DEFAULT_HISTORY_MAX_SIZE),
        )
    }

    fn entry_view(
        &self,
        entry: &Element,
        group: Uuid,
        in_bin: bool,
        with_history: bool,
    ) -> EntryView {
        let (icon_id, custom_icon) = icon_of(entry);
        let (expires, expiry_time) = expiry_of(entry);
        EntryView {
            uuid: uuid_of(entry).unwrap_or_default(),
            group,
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
            times: times_view(entry),
            attachments: binary_refs_of(entry)
                .into_iter()
                .map(|(name, reference)| AttachmentView {
                    size: reference
                        .and_then(|r| self.binaries.get(r))
                        .map_or(0, |b| b.data.len() as u64),
                    name,
                })
                .collect(),
            auto_type: auto_type_of(entry),
            history: if with_history {
                entry
                    .child("History")
                    .map(|h| {
                        h.children_named("Entry")
                            .map(|old| self.entry_view(old, group, in_bin, false))
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            in_recycle_bin: in_bin,
        }
    }

    /// Visits groups in pre-order with their parent and whether an ancestor is the bin.
    fn walk_groups<'a>(
        group: &'a Element,
        parent: Option<Uuid>,
        in_bin: bool,
        bin: Option<Uuid>,
        visit: &mut dyn FnMut(&'a Element, Option<Uuid>, bool),
    ) {
        let uuid = uuid_of(group).unwrap_or_default();
        visit(group, parent, in_bin);
        for child in group.children_named("Group") {
            Self::walk_groups(child, Some(uuid), in_bin || bin == Some(uuid), bin, visit);
        }
    }

    /// All entries in document order, including those in the recycle bin.
    pub fn entries(&self) -> Vec<EntryView> {
        let bin = self.recycle_bin_uuid();
        let mut entries = Vec::new();
        Self::walk_groups(
            self.root_group(),
            None,
            false,
            bin,
            &mut |group, _, in_bin| {
                let uuid = uuid_of(group).unwrap_or_default();
                let in_bin = in_bin || bin == Some(uuid);
                for entry in group.children_named("Entry") {
                    entries.push(self.entry_view(entry, uuid, in_bin, true));
                }
            },
        );
        entries
    }

    /// All groups in document order (pre-order), starting with the root group.
    pub fn groups(&self) -> Vec<GroupView> {
        let bin = self.recycle_bin_uuid();
        let mut groups = Vec::new();
        Self::walk_groups(
            self.root_group(),
            None,
            false,
            bin,
            &mut |group, parent, in_bin| {
                let uuid = uuid_of(group).unwrap_or_default();
                let (icon_id, custom_icon) = icon_of(group);
                let (expires, expiry_time) = expiry_of(group);
                groups.push(GroupView {
                    uuid,
                    parent,
                    name: group.child_text("Name").unwrap_or_default().to_string(),
                    notes: group.child_text("Notes").unwrap_or_default().to_string(),
                    icon_id,
                    custom_icon,
                    expires,
                    expiry_time,
                    times: times_view(group),
                    is_expanded: group
                        .child_text("IsExpanded")
                        .and_then(parse_bool)
                        .unwrap_or(true),
                    is_recycle_bin: bin == Some(uuid),
                    in_recycle_bin: in_bin,
                });
            },
        );
        groups
    }

    pub fn meta(&self) -> MetaView {
        let meta = self.meta_element();
        let (history_max_items, history_max_size) = self.history_limits();
        MetaView {
            name: meta
                .child_text("DatabaseName")
                .unwrap_or_default()
                .to_string(),
            description: meta
                .child_text("DatabaseDescription")
                .unwrap_or_default()
                .to_string(),
            recycle_bin_enabled: meta
                .child_text("RecycleBinEnabled")
                .and_then(parse_bool)
                .unwrap_or(true),
            recycle_bin_uuid: meta
                .child_text("RecycleBinUUID")
                .and_then(parse_uuid)
                .filter(|u| !u.is_nil()),
            history_max_items,
            history_max_size,
        }
    }

    pub fn custom_icons(&self) -> Vec<CustomIconView> {
        self.meta_element()
            .child("CustomIcons")
            .map(|icons| {
                icons
                    .children_named("Icon")
                    .filter_map(|icon| {
                        Some(CustomIconView {
                            uuid: uuid_of(icon)?,
                            png: STANDARD
                                .decode(icon.child_text("Data").unwrap_or_default().trim())
                                .ok()?,
                            name: icon.child_text("Name").unwrap_or_default().to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn binary_named(&self, entry: &Element, name: &str) -> Option<Vec<u8>> {
        binary_refs_of(entry)
            .into_iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, reference)| self.binaries.get(reference?))
            .map(|b| b.data.clone())
    }

    /// Content of the attachment `name` of the current version of `entry`.
    pub fn attachment(&self, entry: Uuid, name: &str) -> Option<Vec<u8>> {
        let path = self.find(entry, Kind::Entry)?;
        self.binary_named(element_at(&self.xml, &path), name)
    }

    /// Content of attachment `name` of history version `index` (oldest first) of `entry`.
    pub fn history_attachment(&self, entry: Uuid, index: usize, name: &str) -> Option<Vec<u8>> {
        let path = self.find(entry, Kind::Entry)?;
        let version = element_at(&self.xml, &path)
            .child("History")?
            .children_named("Entry")
            .nth(index)?;
        self.binary_named(version, name)
    }
}
