//! Utilities for managing database schema changes.
mod migration_schema_v23;

use crate::beacon_chain::BeaconChainTypes;
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::Error as StoreError;

/// Migrate the database from one schema version to another, applying all requisite mutations.
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    from: SchemaVersion,
    to: SchemaVersion,
) -> Result<(), StoreError> {
    match (from, to) {
        // Migrating from the current schema version to itself is always OK, a no-op.
        (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
        // Upgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if from.as_u64() + 1 < to.as_u64() => {
            let next = SchemaVersion(from.as_u64() + 1);
            migrate_schema::<T>(db.clone(), from, next)?;
            migrate_schema::<T>(db, next, to)
        }
        // Downgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if to.as_u64() + 1 < from.as_u64() => {
            let next = SchemaVersion(from.as_u64() - 1);
            migrate_schema::<T>(db.clone(), from, next)?;
            migrate_schema::<T>(db, next, to)
        }

        //
        // Migrations from before SchemaVersion(22) are deprecated.
        //
        (SchemaVersion(22), SchemaVersion(23)) => {
            let ops = migration_schema_v23::upgrade_to_v23::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(23), SchemaVersion(22)) => {
            let ops = migration_schema_v23::downgrade_from_v23::<T>(db.clone())?;
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
