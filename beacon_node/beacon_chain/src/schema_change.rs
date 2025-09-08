//! Utilities for managing database schema changes.
mod migration_schema_v23;
mod migration_schema_v24;
mod migration_schema_v25;
mod migration_schema_v26;
mod migration_schema_v27;
mod migration_schema_v28;

use crate::beacon_chain::BeaconChainTypes;
use std::sync::Arc;
use store::Error as StoreError;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{CURRENT_SCHEMA_VERSION, SchemaVersion};

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
        (SchemaVersion(23), SchemaVersion(24)) => {
            let ops = migration_schema_v24::upgrade_to_v24::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(24), SchemaVersion(23)) => {
            let ops = migration_schema_v24::downgrade_from_v24::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(24), SchemaVersion(25)) => {
            let ops = migration_schema_v25::upgrade_to_v25()?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(25), SchemaVersion(24)) => {
            let ops = migration_schema_v25::downgrade_from_v25()?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(25), SchemaVersion(26)) => {
            let ops = migration_schema_v26::upgrade_to_v26::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(26), SchemaVersion(25)) => {
            let ops = migration_schema_v26::downgrade_from_v26::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(26), SchemaVersion(27)) => {
            // This migration updates the blobs db. The schema version
            // is bumped inside upgrade_to_v27.
            migration_schema_v27::upgrade_to_v27::<T>(db.clone())
        }
        (SchemaVersion(27), SchemaVersion(26)) => {
            // Downgrading is essentially a no-op and is only possible
            // if peer das isn't scheduled.
            migration_schema_v27::downgrade_from_v27::<T>(db.clone())?;
            db.store_schema_version_atomically(to, vec![])
        }
        (SchemaVersion(27), SchemaVersion(28)) => {
            let ops = migration_schema_v28::upgrade_to_v28::<T>(db.clone())?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(28), SchemaVersion(27)) => {
            let ops = migration_schema_v28::downgrade_from_v28::<T>(db.clone())?;
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
