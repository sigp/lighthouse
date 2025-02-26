use crate::blockprint::Config as BlockprintConfig;
use crate::database::Config as DatabaseConfig;
use crate::server::Config as ServerConfig;
use crate::updater::Config as UpdaterConfig;

use serde::{Deserialize, Serialize};
use std::fs::File;

pub const LOG_LEVEL: &str = "debug";

fn log_level() -> String {
    LOG_LEVEL.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub blockprint: BlockprintConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub updater: UpdaterConfig,
    /// The minimum severity for log messages.
    #[serde(default = "log_level")]
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            blockprint: BlockprintConfig::default(),
            database: DatabaseConfig::default(),
            server: ServerConfig::default(),
            updater: UpdaterConfig::default(),
            log_level: log_level(),
        }
    }
}

impl Config {
    pub fn load_from_file(path_to_file: String) -> Result<Config, String> {
        let file =
            File::open(path_to_file).map_err(|e| format!("Error reading config file: {:?}", e))?;
        let config: Config = serde_yaml::from_reader(file)
            .map_err(|e| format!("Error parsing config file: {:?}", e))?;
        Ok(config)
    }
}
