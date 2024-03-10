use crate::error::{Error, Result};
use dirs;
use stamp_core::identity::IdentityID;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

/// Get the current user's data directory.
pub fn data_dir() -> Result<PathBuf> {
    let dir = env::var("STAMP_DIR_DATA")
        .map(|x| PathBuf::from(x))
        .ok()
        .or_else(|| {
            dirs::data_dir().map(|mut x| {
                x.push("stamp");
                x
            })
        })
        .or_else(|| {
            dirs::home_dir().map(|mut x| {
                x.push(".stamp");
                x
            })
        })
        .ok_or(Error::BadHomeDir)?;
    Ok(dir)
}

/// Get the current user's config dir
pub fn config_dir() -> Result<PathBuf> {
    let dir = env::var("STAMP_DIR_CONFIG")
        .map(|x| PathBuf::from(x))
        .ok()
        .or_else(|| {
            dirs::config_dir().map(|mut x| {
                x.push("stamp");
                x
            })
        })
        .or_else(|| {
            dirs::home_dir().map(|mut x| {
                x.push(".stamp");
                x
            })
        })
        .ok_or(Error::BadHomeDir)?;
    Ok(dir)
}

/// Read a file
pub fn load_file(filename: &str) -> Result<Vec<u8>> {
    let file = File::open(filename)?;
    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents)?;
    Ok(contents)
}

#[macro_export]
macro_rules! id_str {
    ($id:expr) => {
        String::try_from($id).map_err(|_| crate::error::Error::ConversionError)
    };
}

#[macro_export]
macro_rules! id_str_split {
    ($id:expr) => {
        match String::try_from($id) {
            Ok(id_full) => {
                let id_short = stamp_core::identity::IdentityID::short(&id_full);
                (id_full, id_short)
            }
            Err(..) => (String::from("<error serializing ID>"), String::from("<error serializing ID>")),
        }
    };
}

/// A message we can send to a UI to tell it about or ask for something.
#[derive(Debug, Clone)]
pub enum UIMessage {
    /// Create a desktop or mobile notification
    Notification { title: String, body: String, icon: Option<String> },
    /// The UI should prompt for a passphrase to unlock the given identity
    UnlockIdentity(IdentityID),
}
