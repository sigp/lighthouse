//! Utilities for managing database schema changes.
mod migration_schema_v12;
mod migration_schema_v13;

use crate::beacon_chain::{BeaconChainTypes, ETH1_CACHE_DB_KEY};
use crate::eth1_chain::SszEth1;
use crate::types::ChainSpec;
use slog::{warn, Logger};
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::{Error as StoreError, StoreItem};

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
        // Migrations from before SchemaVersion(11) are deprecated.
        //

        // Upgrade from v11 to v12 to store richer metadata in the attestation op pool.
        (SchemaVersion(11), SchemaVersion(12)) => {
            let ops = migration_schema_v12::upgrade_to_v12::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        // Downgrade from v12 to v11 to drop richer metadata from the attestation op pool.
        (SchemaVersion(12), SchemaVersion(11)) => {
            let ops = migration_schema_v12::downgrade_from_v12::<T>(db.clone(), log)?;
            db.store_schema_version_atomically(to, ops)
        }
        (SchemaVersion(12), SchemaVersion(13)) => {
            let mut ops = vec![];
            if let Some(persisted_eth1_v1) = db.get_item::<SszEth1>(&ETH1_CACHE_DB_KEY)? {
                let upgraded_eth1_cache =
                    match migration_schema_v13::update_eth1_cache(persisted_eth1_v1) {
                        Ok(upgraded_eth1) => upgraded_eth1,
                        Err(e) => {
                            warn!(log, "Failed to deserialize SszEth1CacheV1"; "error" => ?e);
                            warn!(log, "Reinitializing eth1 cache");
                            migration_schema_v13::reinitialized_eth1_cache_v13(
                                deposit_contract_deploy_block,
                            )
                        }
                    };
                ops.push(upgraded_eth1_cache.as_kv_store_op(ETH1_CACHE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        (SchemaVersion(13), SchemaVersion(12)) => {
            let mut ops = vec![];
            if let Some(persisted_eth1_v13) = db.get_item::<SszEth1>(&ETH1_CACHE_DB_KEY)? {
                let downgraded_eth1_cache = match migration_schema_v13::downgrade_eth1_cache(
                    persisted_eth1_v13,
                ) {
                    Ok(Some(downgraded_eth1)) => downgraded_eth1,
                    Ok(None) => {
                        warn!(log, "Unable to downgrade eth1 cache from newer version: reinitializing eth1 cache");
                        migration_schema_v13::reinitialized_eth1_cache_v1(
                            deposit_contract_deploy_block,
                        )
                    }
                    Err(e) => {
                        warn!(log, "Unable to downgrade eth1 cache from newer version: failed to deserialize SszEth1CacheV13"; "error" => ?e);
                        warn!(log, "Reinitializing eth1 cache");
                        migration_schema_v13::reinitialized_eth1_cache_v1(
                            deposit_contract_deploy_block,
                        )
                    }
                };
                ops.push(downgraded_eth1_cache.as_kv_store_op(ETH1_CACHE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // Anything else is an error.
        (_, _) => Err(HotColdDBError::UnsupportedSchemaVersion {
            target_version: to,
            current_version: from,
        }
        .into()),
    }
}
