//! Error types for kdbx-core

use thiserror::Error;

/// Result type alias for kdbx-core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during KeePass database operations
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to open or parse the database
    #[error("Failed to open database: {0}")]
    OpenError(String),

    /// Failed to save the database
    #[error("Failed to save database: {0}")]
    SaveError(String),

    /// Invalid password or key file
    #[error("Invalid credentials: incorrect password or key file")]
    InvalidCredentials,

    /// Database is locked and requires unlocking
    #[error("Database is locked")]
    DatabaseLocked,

    /// Entry not found
    #[error("Entry not found: {0}")]
    EntryNotFound(uuid::Uuid),

    /// Group not found
    #[error("Group not found: {0}")]
    GroupNotFound(uuid::Uuid),

    /// Invalid entry data
    #[error("Invalid entry data: {0}")]
    InvalidEntry(String),

    /// Invalid group data
    #[error("Invalid group data: {0}")]
    InvalidGroup(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// The database format is not supported
    #[error("Unsupported database format: {0}")]
    UnsupportedFormat(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerializationError(err.to_string())
    }
}
