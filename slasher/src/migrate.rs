use crate::{Error, SlasherDB, database::CURRENT_SCHEMA_VERSION};
use types::EthSpec;

impl<E: EthSpec> SlasherDB<E> {
    /// If the database exists, and has a schema, attempt to migrate it to the current version.
    pub fn migrate(self) -> Result<Self, Error> {
        let mut txn = self.begin_rw_txn()?;
        let schema_version = self.load_schema_version(&mut txn)?;
        drop(txn);

        if let Some(schema_version) = schema_version {
            tracing::info!(
                "Found SlasherDB on-disk schema version v{} (software target v{})",
                schema_version,
                CURRENT_SCHEMA_VERSION
            );
            return match (schema_version, CURRENT_SCHEMA_VERSION) {
                // Schema v3 changed the underlying database from LMDB to MDBX. Unless the user did
                // some manual hacking it should be impossible to read an MDBX schema version < 3.
                (from, _) if from < 3 => {
                    tracing::info!(
                        "SlasherDB schema v{} is older than the supported minimum; refusing to run",
                        from
                    );
                    Err(Error::IncompatibleSchemaVersion {
                        database_schema_version: schema_version,
                        software_schema_version: CURRENT_SCHEMA_VERSION,
                    })
                }
                (x, y) if x == y => {
                    tracing::info!(
                        "SlasherDB schema already at target version v{}; no migration required",
                        y
                    );
                    Ok(self)
                }

                (from, to) if from + 1 == to && self.env.is_redb() => {
                    tracing::info!(
                        "Detected Redb SlasherDB schema v{} -> upgrading to v{}",
                        from,
                        to
                    );
                    self.env.upgrade()?;
                    tracing::info!(
                        "Redb SlasherDB schema upgrade to v{} completed successfully",
                        to
                    );
                    Ok(self)
                }

                (from, to) => {
                    tracing::info!(
                        "SlasherDB schema upgrade path from v{} to v{} is unsupported; refusing to run",
                        from,
                        to
                    );
                    Err(Error::IncompatibleSchemaVersion {
                        database_schema_version: from,
                        software_schema_version: to,
                    })
                }
            };
        }

        tracing::info!(
            "No schema version found, assuming fresh DB at target version v{}",
            CURRENT_SCHEMA_VERSION
        );
        Ok(self)
    }
}
