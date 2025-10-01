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
                (from, _) if from < 3 => Err(Error::IncompatibleSchemaVersion {
                    database_schema_version: schema_version,
                    software_schema_version: CURRENT_SCHEMA_VERSION,
                }),
                (x, y) if x == y => Ok(self),

                (from, to) if from + 1 == to && self.env.is_redb() => {
                    self.env.upgrade()?;
                    let mut txn = self.begin_rw_txn()?;
                    self.store_schema_version(&mut txn)?;
                    txn.commit()?;
                    Ok(self)
                }

                (from, to) => Err(Error::IncompatibleSchemaVersion {
                    database_schema_version: from,
                    software_schema_version: to,
                }),
            };
        }

        // Store the schema version for future runs
        let mut txn = self.begin_rw_txn()?;
        self.store_schema_version(&mut txn)?;
        txn.commit()?;

        Ok(self)
    }
}
