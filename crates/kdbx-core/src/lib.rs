//! kdbx-core - Core KeePass database operations library
//!
//! This crate provides a high-level API for working with KeePass database files (KDBX format).
//! It wraps the `keepass` crate and is designed to compile to WebAssembly for browser usage.

mod database;
mod entry;
mod error;
mod group;

pub use database::Database;
pub use entry::{Entry, EntryBuilder};
pub use error::{Error, Result};
pub use group::Group;

// Re-export types that users might need
pub use uuid::Uuid;
