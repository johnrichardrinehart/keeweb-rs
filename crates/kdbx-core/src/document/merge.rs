//! Three-way merge of two descendants of a common base document, keyed by UUID.
//!
//! Rules, applied per entry and group:
//! - changed on one side: that side wins;
//! - changed differently on both sides: the newer LastModificationTime wins. For entries,
//!   the other version and its history are added to the winner's history;
//! - deleted on one side and unchanged on the other: deleted;
//! - deleted on one side but changed or moved on the other: kept, so no data is lost;
//! - location: the side that moved the item wins; if both did, the newer LocationChanged.
//!
//! The result carries `local`'s outer header (cipher, KDF parameters), so it is saved
//! with the same transformed key as `local`.

use super::edit::{ENTRY_ORDER, META_ORDER, ROOT_ORDER, TIMES_ORDER, order_of};
use super::values::{format_time, now, parse_time};
use super::*;
use std::collections::HashSet;

/// Meta fields grouped by the timestamp that records their last change.
const META_STAMPED: &[(&str, &[&str])] = &[
    ("DatabaseNameChanged", &["DatabaseName"]),
    ("DatabaseDescriptionChanged", &["DatabaseDescription"]),
    ("DefaultUserNameChanged", &["DefaultUserName"]),
    (
        "RecycleBinChanged",
        &["RecycleBinEnabled", "RecycleBinUUID"],
    ),
    ("EntryTemplatesGroupChanged", &["EntryTemplatesGroup"]),
    (
        "SettingsChanged",
        &[
            "MaintenanceHistoryDays",
            "Color",
            "MemoryProtection",
            "HistoryMaxItems",
            "HistoryMaxSize",
            "MasterKeyChangeRec",
            "MasterKeyChangeForce",
        ],
    ),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Local,
    Remote,
}

struct Item {
    kind: Kind,
    /// Groups are stored without their Entry/Group children.
    element: Element,
    parent: Option<Uuid>,
    /// Position among the parent's entries and groups.
    order: usize,
    /// Groups only: where the Entry/Group children started among the remaining children.
    insert_at: usize,
}

struct Indexed {
    root: Uuid,
    items: HashMap<Uuid, Item>,
    /// UUIDs in document order.
    sequence: Vec<Uuid>,
    deleted: Vec<Element>,
}

struct Resolved {
    kind: Kind,
    element: Element,
    parent: Option<Uuid>,
    insert_at: usize,
}

impl Resolved {
    fn from_item(item: &Item) -> Self {
        Self {
            kind: item.kind,
            element: item.element.clone(),
            parent: item.parent,
            insert_at: item.insert_at,
        }
    }
}

/// Indexes the document, importing its binaries into `pool` so attachment references
/// of all three documents are comparable.
fn index(document: &KdbxDocument, pool: &mut BinaryPool) -> Result<Indexed> {
    let mut tree = document.root_group().clone();
    import_binaries(&mut tree, &document.binaries, pool)?;
    let root = uuid_of(&tree).ok_or_else(|| Error::ParseError("Root group has no UUID".into()))?;
    let mut indexed = Indexed {
        root,
        items: HashMap::new(),
        sequence: Vec::new(),
        deleted: document
            .xml
            .child("Root")
            .and_then(|r| r.child("DeletedObjects"))
            .map(|d| d.children_named("DeletedObject").cloned().collect())
            .unwrap_or_default(),
    };
    index_group(tree, None, 0, &mut indexed);
    Ok(indexed)
}

fn index_group(mut group: Element, parent: Option<Uuid>, order: usize, indexed: &mut Indexed) {
    let Some(uuid) = uuid_of(&group) else {
        return;
    };
    indexed.sequence.push(uuid);
    let mut insert_at = None;
    let mut position = 0;
    for child in std::mem::take(&mut group.children) {
        match child.name.as_str() {
            "Entry" => {
                insert_at.get_or_insert(group.children.len());
                if let Some(entry) = uuid_of(&child) {
                    indexed.sequence.push(entry);
                    indexed.items.insert(
                        entry,
                        Item {
                            kind: Kind::Entry,
                            element: child,
                            parent: Some(uuid),
                            order: position,
                            insert_at: 0,
                        },
                    );
                }
                position += 1;
            }
            "Group" => {
                insert_at.get_or_insert(group.children.len());
                index_group(child, Some(uuid), position, indexed);
                position += 1;
            }
            _ => group.children.push(child),
        }
    }
    let insert_at = insert_at.unwrap_or(group.children.len());
    indexed.items.insert(
        uuid,
        Item {
            kind: Kind::Group,
            element: group,
            parent,
            order,
            insert_at,
        },
    );
}

/// Elements whose value is a KDBX boolean, compared case-insensitively.
const BOOLEAN_ELEMENTS: &[&str] = &[
    "Enabled",
    "Expires",
    "EnableAutoType",
    "EnableSearching",
    "QualityCheck",
];

/// Leaf values equivalent to the element being absent.
const DEFAULT_VALUES: &[(&str, &str)] = &[
    ("DataTransferObfuscation", "0"),
    ("EnableAutoType", "null"),
    ("EnableSearching", "null"),
    ("QualityCheck", "True"),
];

/// A form of the element that is equal for semantically equal content, used to detect
/// real changes. Other clients (KeePassXC, the keepass crate) reorder children, omit
/// default or empty elements and change color case when they re-save a file, and
/// that must not count as an edit. Data that changes on mere access, moves or UI
/// interaction is dropped too.
fn canonical(element: &Element, kind: Kind) -> Element {
    let mut canonical = element.clone();
    if kind == Kind::Group {
        canonical
            .children
            .retain(|c| !matches!(c.name.as_str(), "IsExpanded" | "LastTopVisibleEntry"));
    }
    normalize(&mut canonical);
    canonical
}

fn normalize(element: &mut Element) {
    element.children.retain(|c| c.name != "PreviousParentGroup");
    if element.name == "Times" {
        let expires = element.child_text("Expires").and_then(parse_bool) == Some(true);
        element.children.retain(|t| {
            !matches!(
                t.name.as_str(),
                "LastAccessTime" | "UsageCount" | "LocationChanged"
            ) && (expires || t.name != "ExpiryTime")
        });
    }
    for child in &mut element.children {
        normalize(child);
    }

    if element.children.is_empty() {
        if element.text.contains('\r') {
            element.text = element.text.replace("\r\n", "\n");
        }
        if BOOLEAN_ELEMENTS.contains(&element.name.as_str()) {
            if let Some(value) = parse_bool(&element.text) {
                element.text = values::format_bool(value).to_string();
            }
        }
        if matches!(element.name.as_str(), "ForegroundColor" | "BackgroundColor") {
            element.text.make_ascii_uppercase();
        }
    }
    for (key, value) in &mut element.attrs {
        if key == "Protected" {
            if let Some(protected) = parse_bool(value) {
                *value = values::format_bool(protected).to_string();
            }
        }
    }
    element.attrs.sort();

    element.children.retain(|c| {
        let leaf = c.children.is_empty() && c.attrs.is_empty();
        let default = leaf
            && (c.text.is_empty() || DEFAULT_VALUES.contains(&(c.name.as_str(), c.text.as_str())));
        // A string field with an empty value is shown exactly like a missing one.
        let empty_string = c.name == "String"
            && c.child("Value")
                .is_none_or(|v| v.text.is_empty() && v.children.is_empty());
        !default && !empty_string
    });
    element.children.sort();
}

fn label(item: &Item) -> String {
    match item.kind {
        Kind::Entry => entry_title(&item.element),
        Kind::Group => group_name(&item.element),
    }
}

/// Winner's entry with the loser's current version and history merged into its history.
fn merge_versions(winner: &Element, loser: &Element) -> Element {
    let versions = |entry: &Element| -> Vec<Element> {
        entry
            .child("History")
            .map(|h| h.children_named("Entry").cloned().collect())
            .unwrap_or_default()
    };
    let mut history = versions(winner);
    let mut keys: Vec<Element> = history.iter().map(|v| canonical(v, Kind::Entry)).collect();
    let mut loser_current = loser.clone();
    loser_current.remove_children("History");
    for version in versions(loser).into_iter().chain([loser_current]) {
        let key = canonical(&version, Kind::Entry);
        if !keys.contains(&key) {
            keys.push(key);
            history.push(version);
        }
    }
    history.sort_by_key(|v| time_of(v, "LastModificationTime"));

    let mut merged = winner.clone();
    let element = merged.ensure_child("History", ENTRY_ORDER);
    element.children.retain(|c| c.name != "Entry");
    element.children.extend(history);
    merged
}

/// Copies the location bookkeeping (LocationChanged, PreviousParentGroup) of `source`.
fn copy_location(source: &Element, target: &mut Element) {
    let order = order_of(target);
    if let Some(changed) = source
        .child("Times")
        .and_then(|t| t.child("LocationChanged"))
    {
        target
            .ensure_child("Times", order)
            .replace_child(changed.clone(), TIMES_ORDER);
    }
    match source.child("PreviousParentGroup") {
        Some(previous) => target.replace_child(previous.clone(), order),
        None => target.remove_children("PreviousParentGroup"),
    }
}

fn resolve(
    base: Option<&Item>,
    local: Option<&Item>,
    remote: Option<&Item>,
    conflicts: &mut Vec<String>,
) -> Option<Resolved> {
    let content_changed = |side: &Item| {
        base.is_none_or(|b| canonical(&side.element, side.kind) != canonical(&b.element, b.kind))
    };
    match (local, remote) {
        (Some(l), Some(r)) => {
            let (mut element, content_side) = if !content_changed(r) {
                (l.element.clone(), Side::Local)
            } else if !content_changed(l)
                || canonical(&l.element, l.kind) == canonical(&r.element, r.kind)
            {
                let side = if content_changed(l) {
                    Side::Local
                } else {
                    Side::Remote
                };
                let source = if side == Side::Local { l } else { r };
                (source.element.clone(), side)
            } else {
                let remote_newer = time_of(&r.element, "LastModificationTime")
                    > time_of(&l.element, "LastModificationTime");
                let (winner, loser, side) = if remote_newer {
                    (r, l, Side::Remote)
                } else {
                    (l, r, Side::Local)
                };
                conflicts.push(label(winner));
                let element = match winner.kind {
                    Kind::Entry => merge_versions(&winner.element, &loser.element),
                    Kind::Group => winner.element.clone(),
                };
                (element, side)
            };

            let base_parent = base.map(|b| b.parent);
            let (parent, location_side) = if l.parent == r.parent {
                (l.parent, content_side)
            } else if Some(l.parent) == base_parent {
                (r.parent, Side::Remote)
            } else if Some(r.parent) == base_parent {
                (l.parent, Side::Local)
            } else if time_of(&r.element, "LocationChanged")
                > time_of(&l.element, "LocationChanged")
            {
                (r.parent, Side::Remote)
            } else {
                (l.parent, Side::Local)
            };
            if location_side != content_side {
                let source = if location_side == Side::Local { l } else { r };
                copy_location(&source.element, &mut element);
            }

            let content = if content_side == Side::Local { l } else { r };
            Some(Resolved {
                kind: content.kind,
                element,
                parent,
                insert_at: content.insert_at,
            })
        }
        (Some(side), None) | (None, Some(side)) => {
            let deleted_unchanged =
                base.is_some_and(|b| b.parent == side.parent && !content_changed(side));
            (!deleted_unchanged).then(|| Resolved::from_item(side))
        }
        (None, None) => None,
    }
}

fn merge_meta(local: &Element, remote: &Element) -> Element {
    let mut meta = local.clone();
    for (stamp, fields) in META_STAMPED {
        let changed_at = |m: &Element| m.child_text(stamp).and_then(parse_time);
        if changed_at(remote) > changed_at(local) {
            for name in fields.iter().chain([stamp]) {
                match remote.child(name) {
                    Some(value) => meta.replace_child(value.clone(), META_ORDER),
                    None => meta.remove_children(name),
                }
            }
        }
    }

    let remote_icons: Vec<&Element> = remote
        .child("CustomIcons")
        .map(|icons| icons.children_named("Icon").collect())
        .unwrap_or_default();
    let known: HashSet<Uuid> = meta
        .child("CustomIcons")
        .map(|icons| icons.children_named("Icon").filter_map(uuid_of).collect())
        .unwrap_or_default();
    let missing: Vec<Element> = remote_icons
        .into_iter()
        .filter(|icon| uuid_of(icon).is_some_and(|u| !known.contains(&u)))
        .cloned()
        .collect();
    if !missing.is_empty() {
        meta.ensure_child("CustomIcons", META_ORDER)
            .children
            .extend(missing);
    }
    meta
}

fn build_group(
    uuid: Uuid,
    resolved: &mut HashMap<Uuid, Resolved>,
    children: &HashMap<Uuid, Vec<(u8, usize, Uuid)>>,
) -> Element {
    let group = resolved
        .remove(&uuid)
        .expect("every placed group is resolved");
    let mut element = group.element;
    let mut entries = Vec::new();
    let mut groups = Vec::new();
    for &(_, _, child) in children.get(&uuid).map(Vec::as_slice).unwrap_or_default() {
        match resolved.get(&child).map(|r| r.kind) {
            Some(Kind::Entry) => entries.push(resolved.remove(&child).expect("present").element),
            Some(Kind::Group) => groups.push(build_group(child, resolved, children)),
            None => {}
        }
    }
    let at = group.insert_at.min(element.children.len());
    element
        .children
        .splice(at..at, entries.into_iter().chain(groups));
    element
}

/// Merges `local` and `remote`, both derived from `base`.
pub fn merge(
    base: &KdbxDocument,
    local: &KdbxDocument,
    remote: &KdbxDocument,
) -> Result<MergeOutcome> {
    let mut pool = BinaryPool::default();
    let local_ix = index(local, &mut pool)?;
    let remote_ix = index(remote, &mut pool)?;
    let base_ix = index(base, &mut pool)?;
    if local_ix.root != remote_ix.root {
        return Err(Error::SaveError(
            "cannot merge: the remote file is a different database (root groups differ)"
                .to_string(),
        ));
    }
    let root = local_ix.root;

    // Deterministic processing order: local document order, then remote, then base.
    let mut seen = HashSet::new();
    let sequence: Vec<Uuid> = local_ix
        .sequence
        .iter()
        .chain(&remote_ix.sequence)
        .chain(&base_ix.sequence)
        .copied()
        .filter(|u| seen.insert(*u))
        .collect();

    let mut conflicts = Vec::new();
    let mut resolved: HashMap<Uuid, Resolved> = HashMap::new();
    for uuid in &sequence {
        if let Some(r) = resolve(
            base_ix.items.get(uuid),
            local_ix.items.get(uuid),
            remote_ix.items.get(uuid),
            &mut conflicts,
        ) {
            resolved.insert(*uuid, r);
        }
    }

    // Bring back deleted groups that still contain kept items.
    loop {
        let missing: Vec<Uuid> = sequence
            .iter()
            .filter_map(|u| resolved.get(u)?.parent)
            .filter(|p| !resolved.contains_key(p))
            .collect();
        let mut restored = false;
        for parent in missing {
            if resolved.contains_key(&parent) {
                continue;
            }
            let item = [&local_ix, &remote_ix, &base_ix]
                .into_iter()
                .find_map(|ix| ix.items.get(&parent).filter(|i| i.kind == Kind::Group));
            if let Some(item) = item {
                resolved.insert(parent, Resolved::from_item(item));
                restored = true;
            }
        }
        if !restored {
            break;
        }
    }

    // Attach items without a valid parent, and groups caught in a move cycle, to the root.
    let groups: HashSet<Uuid> = resolved
        .iter()
        .filter(|(_, r)| r.kind == Kind::Group)
        .map(|(u, _)| *u)
        .collect();
    for (uuid, item) in resolved.iter_mut() {
        if *uuid == root {
            item.parent = None;
        } else if item.parent.is_none_or(|p| !groups.contains(&p)) {
            item.parent = Some(root);
        }
    }
    for uuid in sequence.iter().filter(|u| groups.contains(u)) {
        let mut visited = HashSet::new();
        let mut current = *uuid;
        while current != root {
            if !visited.insert(current) {
                resolved.get_mut(uuid).expect("group").parent = Some(root);
                break;
            }
            current = resolved[&current].parent.unwrap_or(root);
        }
    }

    // Child order: local order first, then remote-only items in remote order.
    let rank = |uuid: &Uuid, parent: Uuid| -> (u8, usize) {
        [&local_ix, &remote_ix, &base_ix]
            .into_iter()
            .enumerate()
            .find_map(|(i, ix)| {
                ix.items
                    .get(uuid)
                    .filter(|item| item.parent == Some(parent))
                    .map(|item| (i as u8, item.order))
            })
            .unwrap_or((3, 0))
    };
    let mut children: HashMap<Uuid, Vec<(u8, usize, Uuid)>> = HashMap::new();
    for uuid in &sequence {
        if let Some(parent) = resolved.get(uuid).and_then(|r| r.parent) {
            let (bucket, order) = rank(uuid, parent);
            children
                .entry(parent)
                .or_default()
                .push((bucket, order, *uuid));
        }
    }
    for list in children.values_mut() {
        list.sort();
    }

    let kept: HashSet<Uuid> = resolved.keys().copied().collect();
    let root_group = build_group(root, &mut resolved, &children);

    // Deleted objects: union with the latest time per UUID, plus deletions made here,
    // minus everything that survived.
    let mut deleted: Vec<Element> = Vec::new();
    let mut deleted_index: HashMap<Uuid, usize> = HashMap::new();
    let deletion_time = |d: &Element| d.child_text("DeletionTime").and_then(parse_time);
    for record in local_ix.deleted.iter().chain(&remote_ix.deleted) {
        let Some(uuid) = uuid_of(record) else {
            continue;
        };
        match deleted_index.get(&uuid) {
            Some(&i) => {
                if deletion_time(record) > deletion_time(&deleted[i]) {
                    deleted[i] = record.clone();
                }
            }
            None => {
                deleted_index.insert(uuid, deleted.len());
                deleted.push(record.clone());
            }
        }
    }
    let now_text = format_time(now());
    for uuid in &sequence {
        if !kept.contains(uuid) && !deleted_index.contains_key(uuid) {
            deleted.push(Element::with_children(
                "DeletedObject",
                vec![
                    Element::with_text("UUID", values::format_uuid(*uuid)),
                    Element::with_text("DeletionTime", now_text.clone()),
                ],
            ));
        }
    }
    deleted.retain(|d| uuid_of(d).is_none_or(|u| !kept.contains(&u)));

    let mut xml = local.xml.clone();
    let meta = merge_meta(local.meta_element(), remote.meta_element());
    *xml.child_mut("Meta").expect("validated") = meta;
    let group_path = local.root_group_path()?;
    let root_element = &mut xml.children[group_path[0]];
    root_element.children[group_path[1]] = root_group;
    let deleted_objects = root_element.ensure_child("DeletedObjects", ROOT_ORDER);
    deleted_objects
        .children
        .retain(|c| c.name != "DeletedObject");
    deleted_objects.children.extend(deleted);

    Ok(MergeOutcome {
        document: KdbxDocument {
            header: local.header.clone(),
            binaries: pool.into_binaries(),
            xml,
        },
        conflicts,
    })
}
