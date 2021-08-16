use directory::DEFAULT_ROOT_DIR;
use network::NetworkConfig;
use sensitive_url::SensitiveUrl;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use types::{Graffiti, PublicKeyBytes};

/// Default directory name for the freezer database under the top-level data dir.
const DEFAULT_FREEZER_DB_DIR: &str = "freezer_db";

/// Defines how the client should initialize the `BeaconChain` and other components.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    DepositContract,
    /// Loads the genesis state from SSZ-encoded `BeaconState` bytes.
    ///
    /// We include the bytes instead of the `BeaconState<E>` because the `EthSpec` type
    /// parameter would be very annoying.
    SszBytes { genesis_state_bytes: Vec<u8> },
    WeakSubjSszBytes {
        genesis_state_bytes: Vec<u8>,
        anchor_state_bytes: Vec<u8>,
        anchor_block_bytes: Vec<u8>,
    },
    CheckpointSyncUrl {
        genesis_state_bytes: Vec<u8>,
        url: SensitiveUrl,
    },
}

impl Default for ClientGenesis {
    fn default() -> Self {
        Self::DepositContract
    }
}

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
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
    /// A list of hard-coded forks that will be disabled.
    pub disabled_forks: Vec<String>,
    /// Graffiti to be inserted everytime we create a block.
    pub graffiti: Graffiti,
    /// When true, automatically monitor validators using the HTTP API.
    pub validator_monitor_auto: bool,
    /// A list of validator pubkeys to monitor.
    pub validator_monitor_pubkeys: Vec<PublicKeyBytes>,
    #[serde(skip)]
    /// The `genesis` field is not serialized or deserialized by `serde` to ensure it is defined
    /// via the CLI at runtime, instead of from a configuration file saved to disk.
    pub genesis: ClientGenesis,
    pub store: store::StoreConfig,
    pub network: network::NetworkConfig,
    pub chain: beacon_chain::ChainConfig,
    pub eth1: eth1::Config,
    pub http_api: http_api::Config,
    pub http_metrics: http_metrics::Config,
    pub monitoring_api: Option<monitoring_api::Config>,
    pub slasher: Option<slasher::Config>,
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
            disabled_forks: Vec::new(),
            graffiti: Graffiti::default(),
            http_api: <_>::default(),
            http_metrics: <_>::default(),
            monitoring_api: None,
            slasher: None,
            validator_monitor_auto: false,
            validator_monitor_pubkeys: vec![],
        }
    }
}

impl Config {
    /// Get the database path without initialising it.
    pub fn get_db_path(&self) -> Option<PathBuf> {
        self.get_data_dir()
            .map(|data_dir| data_dir.join(&self.db_name))
    }

    /// Get the database path, creating it if necessary.
    pub fn create_db_path(&self) -> Result<PathBuf, String> {
        let db_path = self
            .get_db_path()
            .ok_or("Unable to locate user home directory")?;
        ensure_dir_exists(db_path)
    }

    /// Fetch default path to use for the freezer database.
    fn default_freezer_db_path(&self) -> Option<PathBuf> {
        self.get_data_dir()
            .map(|data_dir| data_dir.join(DEFAULT_FREEZER_DB_DIR))
    }

    /// Returns the path to which the client may initialize the on-disk freezer database.
    ///
    /// Will attempt to use the user-supplied path from e.g. the CLI, or will default
    /// to a directory in the data_dir if no path is provided.
    pub fn get_freezer_db_path(&self) -> Option<PathBuf> {
        self.freezer_db_path
            .clone()
            .or_else(|| self.default_freezer_db_path())
    }

    /// Get the freezer DB path, creating it if necessary.
    pub fn create_freezer_db_path(&self) -> Result<PathBuf, String> {
        let freezer_db_path = self
            .get_freezer_db_path()
            .ok_or("Unable to locate user home directory")?;
        ensure_dir_exists(freezer_db_path)
    }

    /// Returns the core path for the client.
    ///
    /// Will not create any directories.
    pub fn get_data_dir(&self) -> Option<PathBuf> {
        dirs::home_dir().map(|home_dir| home_dir.join(&self.data_dir))
    }

    /// Returns the core path for the client.
    ///
    /// Creates the directory if it does not exist.
    pub fn create_data_dir(&self) -> Result<PathBuf, String> {
        let path = self
            .get_data_dir()
            .ok_or("Unable to locate user home directory")?;
        ensure_dir_exists(path)
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
        let serialized = toml::to_string(&config).expect("should serde encode default config");
        toml::from_str::<Config>(&serialized).expect("should serde decode default config");
    }
}
