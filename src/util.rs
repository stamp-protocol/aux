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

pub fn http_get(url: &str) -> Result<String> {
    let res = ureq::get(url)
        .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .set("Accept-Language", "en-US,en;q=0.5")
        .set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, res) => {
                let res_str = res
                    .into_string()
                    .unwrap_or_else(|e| format!("Could not map error response to string: {:?}", e));
                Error::HttpGet(format!(
                    "Problem calling GET on {}: {} -- {}",
                    url,
                    code,
                    &res_str[0..std::cmp::min(100, res_str.len())]
                ))
            }
            _ => Error::HttpGet(format!("Problem calling GET on {}: {}", url, e)),
        })?
        .into_string();
    Ok(res?)
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
