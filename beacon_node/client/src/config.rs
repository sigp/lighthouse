use beacon_chain::validator_monitor::ValidatorMonitorConfig;
use beacon_processor::BeaconProcessorConfig;
use directory::DEFAULT_ROOT_DIR;
use environment::LoggerConfig;
use network::NetworkConfig;
use sensitive_url::SensitiveUrl;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use types::Graffiti;
/// Default directory name for the freezer database under the top-level data dir.
const DEFAULT_FREEZER_DB_DIR: &str = "freezer_db";

/// Defines how the client should initialize the `BeaconChain` and other components.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ClientGenesis {
    /// Creates a genesis state as per the 2019 Canada interop specifications.
    Interop {
        validator_count: usize,
        genesis_time: u64,
    },
    /// Reads the genesis state and other persisted data from the `Store`.
    FromStore,
    /// Connects to an eth1 node and waits until it can create the genesis state from the deposit
    /// contract.
    #[default]
    DepositContract,
    /// Loads the genesis state from the genesis state in the `Eth2NetworkConfig`.
    GenesisState,
    WeakSubjSszBytes {
        anchor_state_bytes: Vec<u8>,
        anchor_block_bytes: Vec<u8>,
    },
    CheckpointSyncUrl {
        url: SensitiveUrl,
    },
}

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    data_dir: PathBuf,
    /// Name of the directory inside the data directory where the main "hot" DB is located.
    pub db_name: String,
    /// Path where the freezer database will be located.
    pub freezer_db_path: Option<PathBuf>,
    pub log_file: PathBuf,
    /// If true, the node will use co-ordinated junk for eth1 values.
    ///
    /// This is the method used for the 2019 client interop in Canada.
    pub dummy_eth1_backend: bool,
    pub sync_eth1_chain: bool,
    /// Graffiti to be inserted everytime we create a block.
    pub graffiti: Graffiti,
    pub validator_monitor: ValidatorMonitorConfig,
    #[serde(skip)]
    /// The `genesis` field is not serialized or deserialized by `serde` to ensure it is defined
    /// via the CLI at runtime, instead of from a configuration file saved to disk.
    pub genesis: ClientGenesis,
    pub store: store::StoreConfig,
    pub network: network::NetworkConfig,
    pub chain: beacon_chain::ChainConfig,
    pub eth1: eth1::Config,
    pub execution_layer: Option<execution_layer::Config>,
    pub http_api: http_api::Config,
    pub http_metrics: http_metrics::Config,
    pub monitoring_api: Option<monitoring_api::Config>,
    pub slasher: Option<slasher::Config>,
    pub logger_config: LoggerConfig,
    pub beacon_processor: BeaconProcessorConfig,
    pub genesis_state_url: Option<String>,
    pub genesis_state_url_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(DEFAULT_ROOT_DIR),
            db_name: "chain_db".to_string(),
            freezer_db_path: None,
            log_file: PathBuf::from(""),
            genesis: <_>::default(),
            store: <_>::default(),
            network: NetworkConfig::default(),
            chain: <_>::default(),
            dummy_eth1_backend: false,
            sync_eth1_chain: false,
            eth1: <_>::default(),
            execution_layer: None,
            graffiti: Graffiti::default(),
            http_api: <_>::default(),
            http_metrics: <_>::default(),
            monitoring_api: None,
            slasher: None,
            validator_monitor: <_>::default(),
            logger_config: LoggerConfig::default(),
            beacon_processor: <_>::default(),
            genesis_state_url: <_>::default(),
            // This default value should always be overwritten by the CLI default value.
            genesis_state_url_timeout: Duration::from_secs(60),
        }
    }
}

impl Config {
    /// Updates the data directory for the Client.
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir.clone();
        self.http_api.data_dir = data_dir;
    }

    /// Gets the config's data_dir.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Get the database path without initialising it.
    pub fn get_db_path(&self) -> PathBuf {
        self.get_data_dir().join(&self.db_name)
    }

    /// Get the database path, creating it if necessary.
    pub fn create_db_path(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_db_path())
    }

    /// Fetch default path to use for the freezer database.
    fn default_freezer_db_path(&self) -> PathBuf {
        self.get_data_dir().join(DEFAULT_FREEZER_DB_DIR)
    }

    /// Returns the path to which the client may initialize the on-disk freezer database.
    ///
    /// Will attempt to use the user-supplied path from e.g. the CLI, or will default
    /// to a directory in the data_dir if no path is provided.
    pub fn get_freezer_db_path(&self) -> PathBuf {
        self.freezer_db_path
            .clone()
            .unwrap_or_else(|| self.default_freezer_db_path())
    }

    /// Get the freezer DB path, creating it if necessary.
    pub fn create_freezer_db_path(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_freezer_db_path())
    }

    /// Returns the "modern" path to the data_dir.
    ///
    /// See `Self::get_data_dir` documentation for more info.
    fn get_modern_data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    /// Returns the "legacy" path to the data_dir.
    ///
    /// See `Self::get_data_dir` documentation for more info.
    pub fn get_existing_legacy_data_dir(&self) -> Option<PathBuf> {
        dirs::home_dir()
            .map(|home_dir| home_dir.join(&self.data_dir))
            // Return `None` if the legacy directory does not exist or if it is identical to the modern.
            .filter(|dir| dir.exists() && *dir != self.get_modern_data_dir())
    }

    /// Returns the core path for the client.
    ///
    /// Will not create any directories.
    ///
    /// ## Legacy Info
    ///
    /// Legacy versions of Lighthouse did not properly handle relative paths for `--datadir`.
    ///
    /// For backwards compatibility, we still compute the legacy path and check if it exists.  If
    /// it does exist, we use that directory rather than the modern path.
    ///
    /// For more information, see:
    ///
    /// https://github.com/sigp/lighthouse/pull/2843
    pub fn get_data_dir(&self) -> PathBuf {
        let existing_legacy_dir = self.get_existing_legacy_data_dir();

        if let Some(legacy_dir) = existing_legacy_dir {
            legacy_dir
        } else {
            self.get_modern_data_dir()
        }
    }

    /// Returns the core path for the client.
    ///
    /// Creates the directory if it does not exist.
    pub fn create_data_dir(&self) -> Result<PathBuf, String> {
        ensure_dir_exists(self.get_data_dir())
    }
}

/// Ensure that the directory at `path` exists, by creating it and all parents if necessary.
fn ensure_dir_exists(path: PathBuf) -> Result<PathBuf, String> {
    fs::create_dir_all(&path).map_err(|e| format!("Unable to create {}: {}", path.display(), e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let config = Config::default();
        let serialized =
            serde_yaml::to_string(&config).expect("should serde encode default config");
        serde_yaml::from_str::<Config>(&serialized).expect("should serde decode default config");
    }
}
