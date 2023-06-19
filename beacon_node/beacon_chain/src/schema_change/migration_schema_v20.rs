// FIXME(sproul): implement migration
#![allow(unused)]

use crate::{
    beacon_chain::{BeaconChainTypes, BEACON_CHAIN_DB_KEY},
    persisted_beacon_chain::PersistedBeaconChain,
};
use slog::{debug, info, Logger};
use std::collections::HashMap;
use std::sync::Arc;
use store::{
    get_key_for_col,
    hot_cold_store::{HotColdDBError, HotStateSummaryV1, HotStateSummaryV10},
    metadata::SchemaVersion,
    DBColumn, Error, HotColdDB, KeyValueStoreOp, StoreItem,
};
use types::{milhouse::Diff, BeaconState, EthSpec, Hash256, Slot};

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
    /* FIXME(sproul): fix migration
    // Load state summary.
    let HotStateSummaryV1 {
        slot,
        latest_block_root,
        epoch_boundary_state_root,
    } = get_summary_v1::<T>(db, state_root)?;

    // Load full state from the epoch boundary.
    let (epoch_boundary_state, _) = db.load_hot_state_full(&epoch_boundary_state_root)?;

    // Replay blocks to reach the target state.
    let blocks = db.load_blocks_to_replay(epoch_boundary_state.slot(), slot, latest_block_root)?;

    db.replay_blocks(epoch_boundary_state, blocks, slot, std::iter::empty(), None)
    */
    panic!()
}

pub fn upgrade_to_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), Error> {
    /* FIXME(sproul): fix this
    let mut ops = vec![];

    // Translate hot state summaries to new format:
    // - Rewrite epoch boundary root to previous epoch boundary root.
    // - Add previous state root.
    //
    // Replace most epoch boundary states by diffs.
    let split = db.get_split_info();
    let finalized_slot = split.slot;
    let finalized_state_root = split.state_root;
    let slots_per_epoch = T::EthSpec::slots_per_epoch();

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

        debug!(
            log,
            "Re-writing state summaries for head";
            "block_root" => ?head_block_root,
            "state_root" => ?head_state_root,
            "slot" => head_state_slot
        );
        let mut current_state = get_state_by_replay::<T>(&db, head_state_root)?;
        let mut current_state_root = head_state_root;

        new_summaries.insert(
            head_state_root,
            HotStateSummaryV10::new(&head_state_root, &current_state)?,
        );

        for slot in (finalized_slot.as_u64()..current_state.slot().as_u64())
            .rev()
            .map(Slot::new)
        {
            let epoch_boundary_slot = (slot - 1) / slots_per_epoch * slots_per_epoch;

            let state_root = *current_state.get_state_root(slot)?;
            let latest_block_root = *current_state.get_block_root(slot)?;
            let prev_state_root = *current_state.get_state_root(slot - 1)?;
            let epoch_boundary_state_root = *current_state.get_state_root(epoch_boundary_slot)?;

            // FIXME(sproul): rename V10 variant
            let summary = HotStateSummaryV10 {
                slot,
                latest_block_root,
                epoch_boundary_state_root,
                prev_state_root,
            };

            // Stage the updated state summary for storage.
            // If we've reached a known segment of chain then we can stop and continue to the next
            // head.
            if new_summaries.insert(state_root, summary).is_some() {
                debug!(
                    log,
                    "Finished migrating chain tip";
                    "head_block_root" => ?head_block_root,
                    "reason" => format!("reached common state {:?}", state_root),
                );
                break;
            } else {
                debug!(
                    log,
                    "Rewriting hot state summary";
                    "state_root" => ?state_root,
                    "slot" => slot,
                    "epoch_boundary_state_root" => ?epoch_boundary_state_root,
                    "prev_state_root" => ?prev_state_root,
                );
            }

            // If the state reached is an epoch boundary state, then load it so that we can continue
            // backtracking from it and storing diffs.
            if slot % slots_per_epoch == 0 {
                debug!(
                    log,
                    "Loading epoch boundary state";
                    "state_root" => ?state_root,
                    "slot" => slot,
                );
                let backtrack_state = get_state_by_replay::<T>(&db, state_root)?;

                // If the current state is an epoch boundary state too then we might need to convert
                // it to a diff relative to the backtrack state.
                if current_state.slot() % slots_per_epoch == 0
                    && !db.is_stored_as_full_state(current_state_root, current_state.slot())?
                {
                    debug!(
                        log,
                        "Converting full state to diff";
                        "prev_state_root" => ?state_root,
                        "state_root" => ?current_state_root,
                        "slot" => current_state.slot(),
                    );

                    let diff = BeaconStateDiff::compute_diff(&backtrack_state, &current_state)?;

                    // Store diff.
                    ops.push(db.state_diff_as_kv_store_op(&current_state_root, &diff)?);

                    // Delete full state.
                    let state_key = get_key_for_col(
                        DBColumn::BeaconState.into(),
                        current_state_root.as_bytes(),
                    );
                    ops.push(KeyValueStoreOp::DeleteKey(state_key));
                }

                current_state = backtrack_state;
                current_state_root = state_root;
            }

            if slot == finalized_slot {
                // FIXME(sproul): remove assert
                assert_eq!(finalized_state_root, state_root);
                debug!(
                    log,
                    "Finished migrating chain tip";
                    "head_block_root" => ?head_block_root,
                    "reason" => format!("reached finalized state {:?}", finalized_state_root),
                );
                break;
            }
        }
    }

    ops.reserve(new_summaries.len());
    for (state_root, summary) in new_summaries {
        ops.push(summary.as_kv_store_op(state_root)?);
    }

    db.store_schema_version_atomically(SchemaVersion(20), ops)
    */
    panic!()
}

pub fn downgrade_from_v20<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<(), Error> {
    /* FIXME(sproul): broken
    let slots_per_epoch = T::EthSpec::slots_per_epoch();

    // Iterate hot state summaries and re-write them so that:
    //
    // - The previous state root is removed.
    // - The epoch boundary root points to the most recent epoch boundary root rather than the
    //   previous epoch boundary root. We exploit the fact that they are the same except when the slot
    //   of the summary itself lies on an epoch boundary.
    let mut summaries = db
        .iter_hot_state_summaries()
        .collect::<Result<Vec<_>, _>>()?;

    // Sort by slot ascending so that the state cache has a better chance of hitting.
    summaries.sort_unstable_by(|(_, summ1), (_, summ2)| summ1.slot.cmp(&summ2.slot));

    info!(log, "Rewriting {} state summaries", summaries.len());

    let mut ops = Vec::with_capacity(summaries.len());

    for (state_root, summary) in summaries {
        let epoch_boundary_state_root = if summary.slot % slots_per_epoch == 0 {
            info!(
                log,
                "Ensuring state is stored as full state";
                "state_root" => ?state_root,
                "slot" => summary.slot
            );
            let state = db
                .get_hot_state(&state_root)?
                .ok_or(Error::MissingState(state_root))?;

            // Delete state diff.
            let state_key =
                get_key_for_col(DBColumn::BeaconStateDiff.into(), state_root.as_bytes());
            ops.push(KeyValueStoreOp::DeleteKey(state_key));

            // Store full state.
            db.store_full_state_in_batch(&state_root, &state, &mut ops)?;

            // This state root is its own most recent epoch boundary root.
            state_root
        } else {
            summary.epoch_boundary_state_root
        };
        let summary_v1 = HotStateSummaryV1 {
            slot: summary.slot,
            latest_block_root: summary.latest_block_root,
            epoch_boundary_state_root,
        };
        debug!(
            log,
            "Rewriting state summary";
            "slot" => summary_v1.slot,
            "latest_block_root" => ?summary_v1.latest_block_root,
            "epoch_boundary_state_root" => ?summary_v1.epoch_boundary_state_root,
        );

        ops.push(summary_v1.as_kv_store_op(state_root)?);
    }

    db.store_schema_version_atomically(SchemaVersion(8), ops)
    */
    panic!()
}
