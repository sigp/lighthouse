//! Utilities for managing database schema changes.
mod migration_schema_v20;
mod migration_schema_v21;
mod migration_schema_v22;

use crate::beacon_chain::BeaconChainTypes;
use slog::Logger;
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::Error as StoreError;
use types::Hash256;

/// Migrate the database from one schema version to another, applying all requisite mutations.
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    genesis_state_root: Option<Hash256>,
    from: SchemaVersion,
    to: SchemaVersion,
    log: Logger,
) -> Result<(), StoreError> {
    match (from, to) {
        // Migrating from the current schema version to itself is always OK, a no-op.
        (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
        // Upgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if from.as_u64() + 1 < to.as_u64() => {
            let next = SchemaVersion(from.as_u64() + 1);
            migrate_schema::<T>(db.clone(), genesis_state_root, from, next, log.clone())?;
            migrate_schema::<T>(db, genesis_state_root, next, to, log)
        }
        // Downgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if to.as_u64() + 1 < from.as_u64() => {
            let next = SchemaVersion(from.as_u64() - 1);
            migrate_schema::<T>(db.clone(), genesis_state_root, from, next, log.clone())?;
            migrate_schema::<T>(db, genesis_state_root, next, to, log)
        }

        //
        // Migrations from before SchemaVersion(19) are deprecated.
        //
        (SchemaVersion(19), SchemaVersion(20)) => {
            let ops = migration_schema_v20::upgrade_to_v20::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(20), SchemaVersion(19)) => {
            let ops = migration_schema_v20::downgrade_from_v20::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(20), SchemaVersion(21)) => {
            let ops = migration_schema_v21::upgrade_to_v21::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(21), SchemaVersion(20)) => {
            let ops = migration_schema_v21::downgrade_from_v21::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(21), SchemaVersion(22)) => {
            // This migration needs to sync data between hot and cold DBs. The schema version is
            // bumped inside the upgrade_to_v22 fn
            migration_schema_v22::upgrade_to_v22::<T>(db.clone(), genesis_state_root, log)
        }
        // Anything else is an error.
        (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into()),
    }
}
