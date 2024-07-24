//! Utilities for managing database schema changes.
mod migration_schema_v20;
mod migration_schema_v21;

use crate::beacon_chain::BeaconChainTypes;
use crate::types::ChainSpec;
use slog::Logger;
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::Error as StoreError;

/// Migrate the database from one schema version to another, applying all requisite mutations.
#[allow(clippy::only_used_in_recursion)] // spec is not used but likely to be used in future
pub fn migrate_schema<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    deposit_contract_deploy_block: u64,
    from: SchemaVersion,
    to: SchemaVersion,
    log: Logger,
    spec: &ChainSpec,
) -> Result<(), StoreError> {
    match (from, to) {
        // Migrating from the current schema version to itself is always OK, a no-op.
        (_, _) if from == to && to == CURRENT_SCHEMA_VERSION => Ok(()),
        // Upgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if from.as_u64() + 1 < to.as_u64() => {
            let next = SchemaVersion(from.as_u64() + 1);
            migrate_schema::<T>(
                db.clone(),
                deposit_contract_deploy_block,
                from,
                next,
                log.clone(),
                spec,
            )?;
            migrate_schema::<T>(db, deposit_contract_deploy_block, next, to, log, spec)
        }
        // Downgrade across multiple versions by recursively migrating one step at a time.
        (_, _) if to.as_u64() + 1 < from.as_u64() => {
            let next = SchemaVersion(from.as_u64() - 1);
            migrate_schema::<T>(
                db.clone(),
                deposit_contract_deploy_block,
                from,
                next,
                log.clone(),
                spec,
            )?;
            migrate_schema::<T>(db, deposit_contract_deploy_block, next, to, log, spec)
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
        // Anything else is an error.
        (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into()),
    }
}
