//! The main error enum for aux lives here, and documents the various
//! conditions that can arise while interacting with the library.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// Couldn't find the home dir. Sad!
    #[error("bad home dir")]
    BadHomeDir,

    /// A claim failed to verify
    #[error("claim check failed {0}")]
    ClaimCheckFail(String),

    /// Error loading/saving the config
    #[error("config load/save error")]
    ConfigError,

    /// A data conflict
    #[error("conflict: {0}")]
    Conflict(String),

    /// Error converting one thing to another. Probz an ID to a string
    #[error("conversion error")]
    ConversionError,

    /// Error parsing/converting a date
    #[error("date parsing/conversion error: {0}")]
    DateError(#[from] chrono::format::ParseError),

    /// An IO error occured
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// Something was lost
    #[error("not found {0}")]
    NotFound(String),

    /// Error parsing regex
    #[error("error parsing regex: {0}")]
    Regex(#[from] regex::Error),

    /// An error occurred interacting with the SQL db
    #[error("error in storage layer: {0}")]
    Sql(#[from] rusqlite::Error),

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),

    /// An error occurred processing TOML crap
    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),

    /// A value or file provided is too large
    #[error("file/value provided is too large: {0}")]
    TooBig(String),

    /// URL parsing/formatting error
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;


