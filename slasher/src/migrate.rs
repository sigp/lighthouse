use crate::{database::CURRENT_SCHEMA_VERSION, Error, SlasherDB};
use types::EthSpec;

impl<E: EthSpec> SlasherDB<E> {
    /// If the database exists, and has a schema, attempt to migrate it to the current version.
    pub fn migrate(self) -> Result<Self, Error> {
        let mut txn = self.begin_rw_txn()?;
        let schema_version = self.load_schema_version(&mut txn)?;
        drop(txn);

        if let Some(schema_version) = schema_version {
            match (schema_version, CURRENT_SCHEMA_VERSION) {
                // Schema v3 changed the underlying database from LMDB to MDBX. Unless the user did
                // some manual hacking it should be impossible to read an MDBX schema version < 3.
                (from, _) if from < 3 => Err(Error::IncompatibleSchemaVersion {
                    database_schema_version: schema_version,
                    software_schema_version: CURRENT_SCHEMA_VERSION,
                }),
                (x, y) if x == y => Ok(self),
                (_, _) => Err(Error::IncompatibleSchemaVersion {
                    database_schema_version: schema_version,
                    software_schema_version: CURRENT_SCHEMA_VERSION,
                }),
            }
        } else {
            Ok(self)
        }
    }
}
