//! kdbx-diff - Diff and merge library for KeePass databases
//!
//! This crate provides algorithms for comparing and merging KDBX databases.
//! It is designed to compile to WebAssembly for browser-based conflict resolution.

mod diff;
mod merge;
mod types;

pub use diff::DatabaseDiff;
pub use merge::Merger;
pub use types::{Conflict, DiffOperation, EntryDiff, FieldChange, GroupDiff, Resolution, Side};
