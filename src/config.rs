use crate::{
    error::{Error, Result},
    util,
};
use std::{
    fs::File,
    io::{prelude::*, BufReader},
};

#[derive(Clone, Debug, Default, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct NetConfig {
    pub join_list: Vec<String>,
}

#[derive(Clone, Debug, Default, serde_derive::Serialize, serde_derive::Deserialize)]
pub struct Config {
    pub default_identity: Option<String>,
    pub net: Option<NetConfig>,
}

/// Load the local configuration.
pub fn load() -> Result<Config> {
    let data_dir = util::config_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    let mut config_file = data_dir.clone();
    config_file.push("config.toml");
    let config = match File::open(&config_file) {
        Ok(file) => {
            // load and parse
            let mut reader = BufReader::new(file);
            let mut contents = String::new();
            reader.read_to_string(&mut contents)?;
            let config: Config = toml::from_str(&contents).map_err(|_| Error::ConfigError)?;
            config
        }
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => Config::default(),
            _ => Err(Error::ConfigError)?,
        },
    };
    Ok(config)
}

/// Save the current configuration.
pub fn save(config: &Config) -> Result<()> {
    let data_dir = util::config_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    let mut config_file = data_dir.clone();
    config_file.push("config.toml");
    let serialized = toml::to_string_pretty(config).map_err(|_| Error::ConfigError)?;
    let mut handle = File::create(&config_file)?;
    handle.write_all(serialized.as_bytes())?;
    Ok(())
}
