use beacon_chain::builder::PUBKEY_CACHE_FILENAME;
use network::NetworkConfig;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_DATADIR: &str = ".lighthouse";

/// The number initial validators when starting the `Minimal`.
const TESTNET_SPEC_CONSTANTS: &str = "minimal";

/// Default directory name for the freezer database under the top-level data dir.
const DEFAULT_FREEZER_DB_DIR: &str = "freezer_db";

/// Trap file indicating if chain_db was purged
const CHAIN_DB_PURGED_TRAP_FILE: &str = ".db_purged";

/// Defines how the client should initialize the `BeaconChain` and other components.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum ClientGenesis {
    /// Reads the genesis state and other persisted data from the `Store`.
    Resume,
    /// Creates a genesis state as per the 2019 Canada interop specifications.
    Interop {
        validator_count: usize,
        genesis_time: u64,
    },
    /// Connects to an eth1 node and waits until it can create the genesis state from the deposit
    /// contract.
    DepositContract,
    /// Loads the genesis state from a SSZ-encoded `BeaconState` file.
    SszFile { path: PathBuf },
    /// Loads the genesis state from SSZ-encoded `BeaconState` bytes.
    ///
    /// We include the bytes instead of the `BeaconState<E>` because the `EthSpec` type
    /// parameter would be very annoying.
    SszBytes { genesis_state_bytes: Vec<u8> },
    /// Connects to another Lighthouse instance and reads the genesis state and other data via the
    /// HTTP API.
    RemoteNode { server: String, port: Option<u16> },
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
    pub testnet_dir: Option<PathBuf>,
    pub log_file: PathBuf,
    pub spec_constants: String,
    /// If true, the node will use co-ordinated junk for eth1 values.
    ///
    /// This is the method used for the 2019 client interop in Canada.
    pub dummy_eth1_backend: bool,
    pub sync_eth1_chain: bool,
    #[serde(skip)]
    /// The `genesis` field is not serialized or deserialized by `serde` to ensure it is defined
    /// via the CLI at runtime, instead of from a configuration file saved to disk.
    pub genesis: ClientGenesis,
    pub store: store::StoreConfig,
    pub network: network::NetworkConfig,
    pub rest_api: rest_api::Config,
    pub websocket_server: websocket_server::Config,
    pub eth1: eth1::Config,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(DEFAULT_DATADIR),
            db_name: "chain_db".to_string(),
            freezer_db_path: None,
            testnet_dir: None,
            log_file: PathBuf::from(""),
            genesis: <_>::default(),
            store: <_>::default(),
            network: NetworkConfig::default(),
            rest_api: <_>::default(),
            websocket_server: <_>::default(),
            spec_constants: TESTNET_SPEC_CONSTANTS.into(),
            dummy_eth1_backend: false,
            sync_eth1_chain: false,
            eth1: <_>::default(),
        }
    }
}

impl Config {
    /// Get the database path without initialising it.
    pub fn get_db_path(&self) -> Option<PathBuf> {
        self.get_data_dir()
            .map(|data_dir| data_dir.join(&self.db_name))
    }

    /// Get the path of the chain db purged trap file
    pub fn get_db_purged_trap_file_path(&self) -> Option<PathBuf> {
        self.get_data_dir()
            .map(|data_dir| data_dir.join(CHAIN_DB_PURGED_TRAP_FILE))
    }

    /// returns whether chain_db was recently purged
    pub fn chain_db_was_purged(&self) -> bool {
        self.get_db_purged_trap_file_path()
            .map_or(false, |trap_file| trap_file.exists())
    }

    /// purges the chain_db and creates trap file
    pub fn purge_chain_db(&self) -> Result<(), String> {
        // create the trap file
        let trap_file = self
            .get_db_purged_trap_file_path()
            .ok_or("Failed to get trap file path".to_string())?;
        fs::File::create(trap_file)
            .map_err(|err| format!("Failed to create trap file: {}", err))?;

        // remove the chain_db
        fs::remove_dir_all(
            self.get_db_path()
                .ok_or("Failed to get db_path".to_string())?,
        )
        .map_err(|err| format!("Failed to remove chain_db: {}", err))?;

        // remove the freezer db
        fs::remove_dir_all(
            self.get_freezer_db_path()
                .ok_or("Failed to get freezer db path".to_string())?,
        )
        .map_err(|err| format!("Failed to remove chain_db: {}", err))?;

        // also need to remove pubkey cache file if it exists
        let pubkey_cache_file = self
            .get_data_dir()
            .map(|data_dir| data_dir.join(PUBKEY_CACHE_FILENAME))
            .ok_or("Failed to get pubkey cache file path".to_string())?;
        if !pubkey_cache_file.exists() {
            return Ok(());
        }
        fs::remove_file(pubkey_cache_file)
            .map_err(|err| format!("Failed to remove pubkey cache: {}", err))?;

        Ok(())
    }

    /// cleans up purge_db trap file
    pub fn cleanup_after_purge_db(&self) -> Result<(), String> {
        let trap_file = self
            .get_db_purged_trap_file_path()
            .ok_or("Failed to get trap file path".to_string())?;
        if !trap_file.exists() {
            return Ok(());
        }
        fs::remove_file(trap_file).map_err(|err| format!("Failed to remove trap file: {}", err))?;

        Ok(())
    }

    /// Get the database path, creating it if necessary.
    pub fn create_db_path(&self) -> Result<PathBuf, String> {
        let db_path = self
            .get_db_path()
            .ok_or_else(|| "Unable to locate user home directory")?;
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
            .ok_or_else(|| "Unable to locate user home directory")?;
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
            .ok_or_else(|| "Unable to locate user home directory".to_string())?;
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
    use toml;

    #[test]
    fn serde() {
        let config = Config::default();
        let serialized = toml::to_string(&config).expect("should serde encode default config");
        toml::from_str::<Config>(&serialized).expect("should serde decode default config");
    }
}
