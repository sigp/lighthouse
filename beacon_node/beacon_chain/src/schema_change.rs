//! Utilities for managing database schema changes.
mod migration_schema_v29;
mod migration_schema_v30;
mod migration_schema_v31;
mod migration_schema_v32;

use crate::beacon_chain::BeaconChainTypes;
use migration_schema_v29::{downgrade_from_v29, upgrade_to_v29};
use migration_schema_v30::{downgrade_from_v30, upgrade_to_v30};
use migration_schema_v31::{downgrade_from_v31, upgrade_to_v31};
use migration_schema_v32::{downgrade_from_v32, upgrade_to_v32};
use std::sync::Arc;
use store::Error as StoreError;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{CURRENT_SCHEMA_VERSION, SchemaVersion};

/// Migrate the database from one schema version to another, applying all requisite mutations.
///
/// Migrations from schema versions prior to v28 are no longer supported.
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
        // Upgrade from v29 to v30.
        (SchemaVersion(29), SchemaVersion(30)) => {
            let ops = upgrade_to_v30::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v30 to v29.
        (SchemaVersion(30), SchemaVersion(29)) => {
            let ops = downgrade_from_v30::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Upgrade from v30 to v31.
        (SchemaVersion(30), SchemaVersion(31)) => {
            let ops = upgrade_to_v31::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v31 to v30.
        (SchemaVersion(31), SchemaVersion(30)) => {
            let ops = downgrade_from_v31::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Upgrade from v31 to v32.
        (SchemaVersion(31), SchemaVersion(32)) => {
            let ops = upgrade_to_v32::<T>(&db)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v32 to v31.
        (SchemaVersion(32), SchemaVersion(31)) => {
            let ops = downgrade_from_v32::<T>(&db)?;
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
