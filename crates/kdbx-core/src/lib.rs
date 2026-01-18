//! kdbx-core - Core KeePass database operations library
//!
//! This crate provides a high-level API for working with KeePass database files (KDBX format).
//! It wraps the `keepass` crate and is designed to compile to WebAssembly for browser usage.

mod database;
mod entry;
mod error;
mod group;
pub mod kdbx4_decrypt;
pub mod totp;

pub use database::Database;
pub use entry::{Entry, EntryBuilder};
pub use error::{Error, Result};
pub use group::Group;
pub use kdbx4_decrypt::{parse_kdbx4_header, decrypt_kdbx4_with_key, decrypt_kdbx4_full, decrypt_kdbx4_full_with_password, compute_composite_key, KdfParams, KdfType, Kdbx4Header};
pub use totp::{TotpConfig, TotpAlgorithm, TotpError};

// Re-export types that users might need
pub use uuid::Uuid;
