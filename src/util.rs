use crate::error::{Result, Error};
use dirs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

pub fn setup_tracing() -> Result<()> {
    tracing_subscriber::fmt::init();
    Ok(())
}

/// Get the current user's data directory.
pub fn data_dir() -> Result<PathBuf> {
    let mut dir = dirs::data_dir()
        .or_else(|| dirs::home_dir().map(|mut x| { x.push(".stamp"); x }))
        .ok_or(Error::BadHomeDir)?;
    dir.push("stamp");
    Ok(dir)
}

/// Get the current user's config dir
pub fn config_dir() -> Result<PathBuf> {
    let mut dir = dirs::config_dir()
        .or_else(|| dirs::home_dir().map(|mut x| { x.push(".stamp"); x }))
        .ok_or(Error::BadHomeDir)?;
    dir.push("stamp");
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
        String::try_from($id)
            .map_err(|_| crate::error::Error::ConversionError)
    }
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
    }
}

