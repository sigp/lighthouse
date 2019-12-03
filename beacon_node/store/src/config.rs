use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{EthSpec, MinimalEthSpec};

/// Default directory name for the freezer database under the top-level data dir.
const DEFAULT_FREEZER_DB_DIR: &str = "freezer_db";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Name of the directory inside the data directory where the main "hot" DB is located.
    pub db_name: String,
    /// Path where the freezer database will be located.
    pub freezer_db_path: Option<PathBuf>,
    /// Number of slots to wait between storing restore points in the freezer database.
    pub slots_per_restore_point: u64,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            db_name: "chain_db".to_string(),
            freezer_db_path: None,
            slots_per_restore_point: MinimalEthSpec::slots_per_historical_root() as u64,
        }
    }
}

impl StoreConfig {
    pub fn default_freezer_db_dir(&self) -> &'static str {
        DEFAULT_FREEZER_DB_DIR
    }

    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), String> {
        if let Some(freezer_dir) = args.value_of("freezer-dir") {
            self.freezer_db_path = Some(PathBuf::from(freezer_dir));
        }
        if let Some(slots_per_restore_point) = args.value_of("slots-per-restore-point") {
            self.slots_per_restore_point = slots_per_restore_point
                .parse()
                .map_err(|_| "slots-per-restore-point is not a valid integer".to_string())?;
        }
        Ok(())
    }
}
