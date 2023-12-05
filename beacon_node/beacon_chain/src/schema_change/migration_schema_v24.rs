//! Database migration for tree-states
//!
//! High-level list of changes:
//!
//! - Delete all freezer states (if any). Replace genesis state by state in new schema.
//! - Rewrite frozen *block roots* to new schema.
//! - Rewrite OnDiskStoreConfig (done).
//! - Delete pruning checkpoint (done).
//! - Rewrite pubkey cache uncompressed (done).
//! - TODO: either copy all finalized blocks to freezer or add support for linear_blocks=false
//! - Re-store all hot states using diffs & new summary format
//!     - TODO: consider not writing any diffs (?)

use crate::{
    beacon_chain::{BeaconChainTypes, BEACON_CHAIN_DB_KEY},
    persisted_beacon_chain::PersistedBeaconChain,
};
use slog::{debug, info, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use store::{
    get_key_for_col,
    hot_cold_store::{HotColdDBError, HotStateSummaryV1, HotStateSummaryV24},
    metadata::{SchemaVersion, CONFIG_KEY, PRUNING_CHECKPOINT_KEY},
    partial_beacon_state::PartialBeaconState,
    validator_pubkey_cache::DatabasePubkey,
    DBColumn, Error, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem,
};
use types::{BeaconState, Hash256, Slot};

/// Chunk size for freezer block roots in the old database schema.
const OLD_SCHEMA_CHUNK_SIZE: u64 = 128;

pub fn old_schema_chunk_key(cindex: u64) -> [u8; 8] {
    (cindex + 1).to_be_bytes()
}

fn get_summary_v1<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    state_root: Hash256,
) -> Result<HotStateSummaryV1, Error> {
    db.get_item(&state_root)?
        .ok_or_else(|| HotColdDBError::MissingHotStateSummary(state_root).into())
}

fn get_state_by_replay<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    state_root: Hash256,
) -> Result<BeaconState<T::EthSpec>, Error> {
    // Load state summary.
    let HotStateSummaryV1 {
        slot,
        latest_block_root,
        diff_base_state_root: epoch_boundary_state_root,
    } = get_summary_v1::<T>(db, state_root)?;

    // Load full state from the epoch boundary.
    let epoch_boundary_state_bytes = db
        .hot_db
        .get_bytes(
            DBColumn::BeaconState.into(),
            epoch_boundary_state_root.as_bytes(),
        )?
        .ok_or(HotColdDBError::MissingEpochBoundaryState(state_root))?;
    let epoch_boundary_state =
        BeaconState::from_ssz_bytes(&epoch_boundary_state_bytes, db.get_chain_spec())?;

    // Replay blocks to reach the target state.
    let blocks = db.load_blocks_to_replay(epoch_boundary_state.slot(), slot, latest_block_root)?;

    db.replay_blocks(epoch_boundary_state, blocks, slot, std::iter::empty(), None)
}

/// Load a restore point state by its `state_root`.
fn load_old_schema_restore_point<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    state_root: Hash256,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    let Some(partial_state_bytes) = db
        .cold_db
        .get_bytes(DBColumn::BeaconState.into(), state_root.as_bytes())?
    else {
        return Ok(None);
    };
    let mut partial_state: PartialBeaconState<T::EthSpec> =
        PartialBeaconState::from_ssz_bytes(&partial_state_bytes, db.get_chain_spec())?;

    // Fill in the fields of the partial state.
    partial_state.load_block_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_state_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_historical_roots(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_randao_mixes(&db.cold_db, db.get_chain_spec())?;
    partial_state.load_historical_summaries(&db.cold_db, db.get_chain_spec())?;

    partial_state.try_into().map(Some)
}

fn load_old_schema_genesis_state<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    genesis_state_root: Hash256,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    load_old_schema_restore_point::<T>(db, genesis_state_root)
}

fn upgrade_freezer_database<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    genesis_state_root: Hash256,
    genesis_state: &BeaconState<T::EthSpec>,
    log: &Logger,
) -> Result<(), Error> {
    let mut cold_db_ops = vec![];

    // 1. Delete all freezer states & re-store genesis.
    db.prune_historic_states(genesis_state_root, genesis_state, &mut cold_db_ops)?;

    // 2. Re-write the beacon block roots array.
    let mut freezer_block_roots = vec![];
    let oldest_block_slot = db.get_oldest_block_slot();
    let mut current_slot = oldest_block_slot;

    for result in db
        .cold_db
        .iter_column::<Vec<u8>>(DBColumn::BeaconBlockRoots)
    {
        let (chunk_key, chunk_bytes) = result?;

        // Stage this chunk for deletion.
        cold_db_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
            DBColumn::BeaconBlockRoots.into(),
            &chunk_key,
        )));

        // Skip the 0x0 key which is for the genesis block.
        if chunk_key.iter().all(|b| *b == 0u8) {
            continue;
        }

        let current_chunk_index = current_slot.as_u64() / OLD_SCHEMA_CHUNK_SIZE;
        if chunk_key != old_schema_chunk_key(current_chunk_index).as_slice() {
            return Err(Error::DBError {
                message: format!(
                    "expected chunk index {} but got {:?}",
                    current_chunk_index, chunk_key
                ),
            });
        }

        for (i, block_root_bytes) in chunk_bytes.chunks_exact(32).enumerate() {
            let block_root = Hash256::from_slice(&block_root_bytes);

            if block_root.is_zero() {
                continue;
            }

            let slot = Slot::new(current_chunk_index * OLD_SCHEMA_CHUNK_SIZE + i as u64);
            if slot != current_slot {
                return Err(Error::DBError {
                    message: format!(
                        "expected block root for slot {} but got {}",
                        current_slot, slot
                    ),
                });
            }
            freezer_block_roots.push((slot, block_root));
            current_slot += 1;
        }
    }

    // Write the freezer block roots in the new schema.
    for (slot, block_root) in freezer_block_roots {
        cold_db_ops.push(KeyValueStoreOp::PutKeyValue(
            get_key_for_col(
                DBColumn::BeaconBlockRoots.into(),
                &slot.as_u64().to_be_bytes(),
            ),
            block_root.as_bytes().to_vec(),
        ));
    }

    db.cold_db.do_atomically(cold_db_ops)?;
    info!(
        log,
        "Freezer database upgrade complete";
        "oldest_block_slot" => oldest_block_slot,
        "newest_block_slot" => current_slot - 1
    );

    Ok(())
}

fn upgrade_store_config<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    hot_db_ops: &mut Vec<KeyValueStoreOp>,
    _log: &Logger,
) -> Result<(), Error> {
    // Overwrite the previous config with the new one from memory. It doesn't matter what it was,
    // slots-per-restore-point is irrelevant as we've deleted all the freezer states.
    let on_disk_config = db.get_config().as_disk_config();
    if on_disk_config.linear_blocks {
        return Err(Error::DBError {
            message: format!("un-upgraded node should have linear_blocks=false"),
        });
    }
    hot_db_ops.push(on_disk_config.as_kv_store_op(CONFIG_KEY)?);
    Ok(())
}

fn delete_pruning_checkpoint<T: BeaconChainTypes>(
    hot_db_ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    // Pruning checkpoint is no longer stored, we use the split.
    debug!(log, "Deleting the on-disk pruning checkpoint");
    hot_db_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
        DBColumn::BeaconMeta.into(),
        PRUNING_CHECKPOINT_KEY.as_bytes(),
    )));
    Ok(())
}

fn upgrade_pubkey_cache<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    hot_db_ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    // De-compress all public keys.
    info!(
        log,
        "Rewriting on-disk public key storage";
        "note" => "this may take several minutes"
    );
    let mut count = 0;
    for res in db.hot_db.iter_column::<Hash256>(DBColumn::PubkeyCache) {
        let (key, compressed_pubkey_bytes) = res?;
        let new_value = DatabasePubkey::from_legacy_pubkey_bytes(&compressed_pubkey_bytes)?;
        hot_db_ops.push(new_value.as_kv_store_op(key)?);
        count += 1;
    }
    info!(
        log,
        "Finished re-writing on-disk public keys";
        "num_keys" => count,
    );
    Ok(())
}

fn rewrite_hot_states<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    hot_db_ops: &mut Vec<KeyValueStoreOp>,
    log: &Logger,
) -> Result<(), Error> {
    // Rewrite the split state and delete everything else from the `BeaconState` column.
    let split = db.get_split_info();
    let mut split_state_found = false;

    for res in db.hot_db.iter_column::<Hash256>(DBColumn::BeaconState) {
        let (state_root, state_bytes) = res?;

        if state_root == split.state_root {
            let state = BeaconState::from_ssz_bytes(&state_bytes, db.get_chain_spec())?;
            db.store_hot_state(&state_root, &state, hot_db_ops)?;
            split_state_found = true;
        } else {
            // Delete.
            hot_db_ops.push(KeyValueStoreOp::DeleteKey(get_key_for_col(
                DBColumn::BeaconState.into(),
                state_root.as_bytes(),
            )));
        }
    }

    if !split_state_found {
        return Err(HotColdDBError::MissingSplitState(split.state_root, split.slot).into());
    }

    // Rewrite the hot state summaries *without* using any state diffs.
    //
    // The complicated state-loading is unfortunately required so that we can compute
    // previous state roots and add them to the state summaries.
    let ssz_head_tracker = db
        .get_item::<PersistedBeaconChain>(&BEACON_CHAIN_DB_KEY)?
        .ok_or(Error::MissingPersistedBeaconChain)?
        .ssz_head_tracker;

    let mut new_summaries = HashMap::new();

    for (head_block_root, head_state_slot) in ssz_head_tracker
        .roots
        .into_iter()
        .zip(ssz_head_tracker.slots)
    {
        let block = db
            .get_blinded_block(&head_block_root, Some(head_state_slot))?
            .ok_or(Error::BlockNotFound(head_block_root))?;
        let head_state_root = block.state_root();

        info!(
            log,
            "Re-writing state summaries for head";
            "block_root" => ?head_block_root,
            "state_root" => ?head_state_root,
            "slot" => head_state_slot
        );
        let current_state = get_state_by_replay::<T>(&db, head_state_root)?;

        new_summaries.insert(
            head_state_root,
            HotStateSummaryV24::new(&head_state_root, &current_state, None)?,
        );

        for slot in (split.slot.as_u64()..current_state.slot().as_u64())
            .rev()
            .map(Slot::new)
        {
            // FIXME(sproul): think about whether to handle long distances from the split. we
            // probably should.
            let state_root = *current_state.get_state_root(slot)?;
            let latest_block_root = *current_state.get_block_root(slot)?;
            let prev_state_root = *current_state.get_state_root(slot - 1)?;

            let summary = HotStateSummaryV24 {
                slot,
                latest_block_root,
                diff_base_state_root: Hash256::zero(),
                diff_base_slot: Slot::new(0),
                prev_state_root,
            };

            // Stage the updated state summary for storage.
            // If we've reached a known segment of chain then we can stop and continue to the next
            // head.
            if new_summaries.insert(state_root, summary).is_some() {
                info!(
                    log,
                    "Finished migrating chain tip";
                    "head_block_root" => ?head_block_root,
                    "reason" => format!("reached common state {state_root:?}"),
                );
                break;
            } else {
                debug!(
                    log,
                    "Rewriting hot state summary";
                    "state_root" => ?state_root,
                    "slot" => slot,
                    "prev_state_root" => ?prev_state_root,
                );
            }

            if slot == split.slot {
                if state_root != split.state_root {
                    return Err(Error::DBError {
                        message: format!(
                            "reached split slot but state root is wrong: {} != {}",
                            state_root, split.state_root
                        ),
                    });
                }
                info!(
                    log,
                    "Finished migrating chain tip";
                    "head_block_root" => ?head_block_root,
                    "reason" => format!("reached split state {state_root:?}"),
                );
                break;
            }
        }
    }

    hot_db_ops.reserve(new_summaries.len());

    for (state_root, summary) in new_summaries {
        hot_db_ops.push(summary.as_kv_store_op(state_root)?);
    }

    Ok(())
}

fn upgrade_hot_database<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
    log: &Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut hot_db_ops = vec![];
    upgrade_store_config::<T>(db, &mut hot_db_ops, log)?;
    delete_pruning_checkpoint::<T>(&mut hot_db_ops, log)?;
    upgrade_pubkey_cache::<T>(db, &mut hot_db_ops, log)?;
    rewrite_hot_states::<T>(db, &mut hot_db_ops, log)?;
    Ok(hot_db_ops)
}

pub fn upgrade_to_v24<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    opt_genesis_state_root: Option<Hash256>,
    log: Logger,
) -> Result<(), Error> {
    let genesis_state_root = opt_genesis_state_root.ok_or_else(|| Error::DBError {
        message: "network genesis is not known, nothing to migrate".into(),
    })?;
    // Migrate the freezer first. If the old-schema genesis state isn't found then we assume that
    // the freezer migration has already run and we are re-running due to an exit before the hot DB
    // migration completed.
    if let Some(genesis_state) = load_old_schema_genesis_state::<T>(&db, genesis_state_root)? {
        info!(log, "Upgrading freezer database schema");
        upgrade_freezer_database::<T>(&db, genesis_state_root, &genesis_state, &log)?;
    } else {
        info!(
            log,
            "Skipping freezer upgrade";
            "note" => "already upgraded or DB empty"
        );
    };
    let hot_db_ops = upgrade_hot_database::<T>(&db, &log)?;

    db.store_schema_version_atomically(SchemaVersion(24), hot_db_ops)
}
