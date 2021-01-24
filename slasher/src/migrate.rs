use crate::{database::CURRENT_SCHEMA_VERSION, Config, Error, SlasherDB};
use lmdb::RwTransaction;
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;
use types::EthSpec;

/// Config from schema version 1, for migration to version 2+.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigV1 {
    database_path: PathBuf,
    chunk_size: usize,
    validator_chunk_size: usize,
    history_length: usize,
    update_period: u64,
    max_db_size_mbs: usize,
}

type ConfigV2 = Config;

impl Into<ConfigV2> for ConfigV1 {
    fn into(self) -> ConfigV2 {
        Config {
            database_path: self.database_path,
            chunk_size: self.chunk_size,
            validator_chunk_size: self.validator_chunk_size,
            history_length: self.history_length,
            update_period: self.update_period,
            max_db_size_mbs: self.max_db_size_mbs,
            broadcast: false,
        }
    }
}

impl<E: EthSpec> SlasherDB<E> {
    /// If the database exists, and has a schema, attempt to migrate it to the current version.
    pub fn migrate(&self, txn: &mut RwTransaction<'_>) -> Result<(), Error> {
        if let Some(schema_version) = self.load_schema_version(txn)? {
            match (schema_version, CURRENT_SCHEMA_VERSION) {
                // The migration from v1 to v2 is a bit messy because v1.0.5 silently
                // changed the schema to v2, so a v1 schema could have either a v1 or v2
                // config.
                (1, 2) => {
                    match self.load_config::<ConfigV1>(txn) {
                        Ok(Some(config_v1)) => {
                            // Upgrade to v2 config and store on disk.
                            let config_v2 = config_v1.into();
                            self.store_config(&config_v2, txn)?;
                        }
                        Ok(None) => {
                            // Impossible to have schema version and no config.
                            return Err(Error::ConfigMissing);
                        }
                        Err(_) => {
                            // If loading v1 config failed, ensure loading v2 config succeeds.
                            // No further action is needed.
                            let _config_v2 = self.load_config::<ConfigV2>(txn)?;
                        }
                    }
                }
                (x, y) if x == y => {}
                (_, _) => {
                    return Err(Error::IncompatibleSchemaVersion {
                        database_schema_version: schema_version,
                        software_schema_version: CURRENT_SCHEMA_VERSION,
                    });
                }
            }
        }

        // If the migration succeeded, update the schema version on-disk.
        self.store_schema_version(txn)?;
        Ok(())
    }
}
