//! Utilities for managing database schema changes.
mod migration_schema_v17;
mod migration_schema_v18;
mod migration_schema_v19;
mod migration_schema_v24;

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
        // Upgrade for tree-states database changes. There is no downgrade.
        (SchemaVersion(19), SchemaVersion(24)) => {
            migration_schema_v24::upgrade_to_v24::<T>(db, genesis_state_root, log)
        }
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
        // Migrations from before SchemaVersion(16) are deprecated.
        //
        (SchemaVersion(16), SchemaVersion(17)) => {
            let ops = migration_schema_v17::upgrade_to_v17::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(17), SchemaVersion(16)) => {
            let ops = migration_schema_v17::downgrade_from_v17::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(17), SchemaVersion(18)) => {
            let ops = migration_schema_v18::upgrade_to_v18::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(18), SchemaVersion(17)) => {
            let ops = migration_schema_v18::downgrade_from_v18::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(18), SchemaVersion(19)) => {
            let ops = migration_schema_v19::upgrade_to_v19::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(19), SchemaVersion(18)) => {
            let ops = migration_schema_v19::downgrade_from_v19::<T>(db.clone(), log)?;
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
