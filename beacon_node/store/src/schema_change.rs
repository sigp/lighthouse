//! Utilities for managing database schema changes.
use crate::hot_cold_store::{HotColdDB, HotColdDBError};
use crate::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use crate::{Error, ItemStore};
use types::EthSpec;

impl<E, Hot, Cold> HotColdDB<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    /// Migrate the database from one schema version to another, applying all requisite mutations.
    pub fn migrate_schema(&self, from: SchemaVersion, to: SchemaVersion) -> Result<(), Error> {
        match (from, to) {
            // Migration from v0.3.0 to v0.3.x, adding the temporary states column.
            // Nothing actually needs to be done, but once a DB uses v2 it shouldn't go back.
            (SchemaVersion(1), SchemaVersion(2)) => {
                self.store_schema_version(to)?;
                Ok(())
            }
            // Migrating from the current schema version to iself is always OK, a no-op.
            (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
            // Anything else is an error.
            (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
                target_version: to,
                current_version: from,
            }
            .into()),
        }
    }
}
