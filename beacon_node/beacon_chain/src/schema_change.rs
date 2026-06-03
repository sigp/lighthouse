//! Utilities for managing database schema changes.
mod migration_schema_v29;

use crate::beacon_chain::BeaconChainTypes;
use migration_schema_v29::{downgrade_from_v29, upgrade_to_v29};
use std::sync::Arc;
use store::Error as StoreError;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{CURRENT_SCHEMA_VERSION, SchemaVersion};

/// Migrate the database from one schema version to another, applying all requisite mutations.
///
/// All migrations for schema versions up to and including v28 have been removed. Nodes on live
/// networks are already running v28, so only the current version check remains.
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    from: SchemaVersion,
    to: SchemaVersion,
) -> Result<(), StoreError> {
    match (from, to) {
        // Migrating from the current schema version to itself is always OK, a no-op.
        (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
        // Upgrade from v28 to v29.
        (SchemaVersion(28), SchemaVersion(29)) => {
            let ops = upgrade_to_v29::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v29 to v28.
        (SchemaVersion(29), SchemaVersion(28)) => {
            let ops = downgrade_from_v29::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Anything else is an error.
        (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into()),
    }
}
