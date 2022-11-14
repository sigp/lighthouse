//! Utilities for managing database schema changes.
mod migration_schema_v10;
mod migration_schema_v11;
mod migration_schema_v12;
mod migration_schema_v13;
mod migration_schema_v6;
mod migration_schema_v7;
mod migration_schema_v8;
mod migration_schema_v9;
mod types;

use crate::beacon_chain::{BeaconChainTypes, ETH1_CACHE_DB_KEY, FORK_CHOICE_DB_KEY};
use crate::eth1_chain::SszEth1;
use crate::persisted_fork_choice::{
    PersistedForkChoiceV1, PersistedForkChoiceV10, PersistedForkChoiceV11, PersistedForkChoiceV7,
    PersistedForkChoiceV8,
};
use crate::types::ChainSpec;
use slog::{warn, Logger};
use std::sync::Arc;
use store::hot_cold_store::{HotColdDB, HotColdDBError};
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::{Error as StoreError, StoreItem};

/// Migrate the database from one schema version to another, applying all requisite mutations.
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
        // Migrations from before SchemaVersion(5) are deprecated.
        //

        // Migration for adding `execution_status` field to the fork choice store.
        (SchemaVersion(5), SchemaVersion(6)) => {
            // Database operations to be done atomically
            let mut ops = vec![];

            // The top-level `PersistedForkChoice` struct is still V1 but will have its internal
            // bytes for the fork choice updated to V6.
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV1>(&FORK_CHOICE_DB_KEY)?;
            if let Some(mut persisted_fork_choice) = fork_choice_opt {
                migration_schema_v6::update_execution_statuses::<T>(&mut persisted_fork_choice)
                    .map_err(StoreError::SchemaMigrationError)?;

                // Store the converted fork choice store under the same key.
                ops.push(persisted_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // 1. Add `proposer_boost_root`.
        // 2. Update `justified_epoch` to `justified_checkpoint` and `finalized_epoch` to
        //  `finalized_checkpoint`.
        // 3. This migration also includes a potential update to the justified
        //  checkpoint in case the fork choice store's justified checkpoint and finalized checkpoint
        //  combination does not actually exist for any blocks in fork choice. This was possible in
        //  the consensus spec prior to v1.1.6.
        //
        // Relevant issues:
        //
        // https://github.com/sigp/lighthouse/issues/2741
        // https://github.com/ethereum/consensus-specs/pull/2727
        // https://github.com/ethereum/consensus-specs/pull/2730
        (SchemaVersion(6), SchemaVersion(7)) => {
            // Database operations to be done atomically
            let mut ops = vec![];

            let fork_choice_opt = db.get_item::<PersistedForkChoiceV1>(&FORK_CHOICE_DB_KEY)?;
            if let Some(persisted_fork_choice_v1) = fork_choice_opt {
                // This migrates the `PersistedForkChoiceStore`, adding the `proposer_boost_root` field.
                let mut persisted_fork_choice_v7 = persisted_fork_choice_v1.into();

                let result = migration_schema_v7::update_fork_choice::<T>(
                    &mut persisted_fork_choice_v7,
                    db.clone(),
                );

                // Fall back to re-initializing fork choice from an anchor state if necessary.
                if let Err(e) = result {
                    warn!(log, "Unable to migrate to database schema 7, re-initializing fork choice"; "error" => ?e);
                    migration_schema_v7::update_with_reinitialized_fork_choice::<T>(
                        &mut persisted_fork_choice_v7,
                        db.clone(),
                        spec,
                    )
                    .map_err(StoreError::SchemaMigrationError)?;
                }

                // Store the converted fork choice store under the same key.
                ops.push(persisted_fork_choice_v7.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // Migration to add an `epoch` key to the fork choice's balances cache.
        (SchemaVersion(7), SchemaVersion(8)) => {
            let mut ops = vec![];
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV7>(&FORK_CHOICE_DB_KEY)?;
            if let Some(fork_choice) = fork_choice_opt {
                let updated_fork_choice =
                    migration_schema_v8::update_fork_choice::<T>(fork_choice, db.clone())?;

                ops.push(updated_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // Upgrade from v8 to v9 to separate the execution payloads into their own column.
        (SchemaVersion(8), SchemaVersion(9)) => {
            migration_schema_v9::upgrade_to_v9::<T>(db.clone(), log)?;
            db.store_schema_version(to)
        }
        // Downgrade from v9 to v8 to ignore the separation of execution payloads
        // NOTE: only works before the Bellatrix fork epoch.
        (SchemaVersion(9), SchemaVersion(8)) => {
            migration_schema_v9::downgrade_from_v9::<T>(db.clone(), log)?;
            db.store_schema_version(to)
        }
        (SchemaVersion(9), SchemaVersion(10)) => {
            let mut ops = vec![];
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV8>(&FORK_CHOICE_DB_KEY)?;
            if let Some(fork_choice) = fork_choice_opt {
                let updated_fork_choice = migration_schema_v10::update_fork_choice(fork_choice)?;

                ops.push(updated_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        (SchemaVersion(10), SchemaVersion(9)) => {
            let mut ops = vec![];
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV10>(&FORK_CHOICE_DB_KEY)?;
            if let Some(fork_choice) = fork_choice_opt {
                let updated_fork_choice = migration_schema_v10::downgrade_fork_choice(fork_choice)?;

                ops.push(updated_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // Upgrade from v10 to v11 adding support for equivocating indices to fork choice.
        (SchemaVersion(10), SchemaVersion(11)) => {
            let mut ops = vec![];
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV10>(&FORK_CHOICE_DB_KEY)?;
            if let Some(fork_choice) = fork_choice_opt {
                let updated_fork_choice = migration_schema_v11::update_fork_choice(fork_choice);

                ops.push(updated_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
        // Downgrade from v11 to v10 removing support for equivocating indices from fork choice.
        (SchemaVersion(11), SchemaVersion(10)) => {
            let mut ops = vec![];
            let fork_choice_opt = db.get_item::<PersistedForkChoiceV11>(&FORK_CHOICE_DB_KEY)?;
            if let Some(fork_choice) = fork_choice_opt {
                let updated_fork_choice =
                    migration_schema_v11::downgrade_fork_choice(fork_choice, log);

                ops.push(updated_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY));
            }

            db.store_schema_version_atomically(to, ops)?;

            Ok(())
        }
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
