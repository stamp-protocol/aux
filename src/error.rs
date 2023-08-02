//! The main error enum for aux lives here, and documents the various
//! conditions that can arise while interacting with the library.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// Couldn't find an admin key that allows the transaction to verify
    #[error("could not find admin key that satisfies a policy for the transaction")]
    AdminKeyNotFound,

    /// Couldn't find the home dir. Sad!
    #[error("bad home dir")]
    BadHomeDir,

    /// Channel send error
    #[error("channel send: {0}")]
    ChannelSend(String),

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

    /// Failed to deserialize a value
    #[error("failed to deserialize a value")]
    DeserializeFailure,

    /// Failed to resolve a DNS address
    #[error("dns lookup failure: {0}")]
    DnsLookupFailure(String),

    /// Expected exactly one identity, found multiple
    #[error("expected exactly one identity with id {0} but found multiple")]
    IdentityCollision(String),

    /// Invalid protocol given, probably a bad [Multiaddr][stamp_net::Multiaddr]
    #[error("invalid protocol given: {0}")]
    InvalidProtocol(String),

    /// An IO error occured
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// Failed to properly generate a key
    #[error("key generation failed")]
    KeygenFailed,

    /// Failed ot set up logging
    #[error("failed to set up logging")]
    LoggingInit,

    /// StampNet error
    #[error("StampNet error: {0}")]
    Net(#[from] stamp_net::Error),

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

    /// An error occured joining a task
    #[error("task join error: {0}")]
    Task(#[from] tokio::task::JoinError),

    /// An error occurred processing TOML crap
    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),

    /// A value or file provided is too large
    #[error("file/value provided is too large: {0}")]
    TooBig(String),

    /// Error setting up tracing lib
    #[error("error setting up tracing")]
    Tracing(String),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;


