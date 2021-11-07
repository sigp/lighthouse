use crate::{database::CURRENT_SCHEMA_VERSION, Error, SlasherDB};
use slog::info;
use std::fs;
use types::EthSpec;

impl<E: EthSpec> SlasherDB<E> {
    /// If the database exists, and has a schema, attempt to migrate it to the current version.
    pub fn migrate(self) -> Result<Self, Error> {
        let mut txn = self.begin_rw_txn()?;
        let schema_version = self.load_schema_version(&mut txn)?;
        drop(txn);

        let db = if let Some(schema_version) = schema_version {
            match (schema_version, CURRENT_SCHEMA_VERSION) {
                // Schema v3 was a backwards-incompatible change for which proper migration would
                // be too fiddly to implement and slow to run, so we delete the database and
                // re-initialize it in that case.
                (from, _) if from < 3 => {
                    let log = self.log.clone();
                    let config = self.config.clone();
                    drop(self);

                    info!(
                        log,
                        "Re-initializing slasher database";
                        "prev_version" => from,
                        "new_version" => CURRENT_SCHEMA_VERSION,
                    );

                    fs::remove_dir_all(&config.database_path)?;

                    Self::open(config, log)?
                }
                (x, y) if x == y => self,
                (_, _) => {
                    return Err(Error::IncompatibleSchemaVersion {
                        database_schema_version: schema_version,
                        software_schema_version: CURRENT_SCHEMA_VERSION,
                    });
                }
            }
        } else {
            self
        };

        Ok(db)
    }
}
