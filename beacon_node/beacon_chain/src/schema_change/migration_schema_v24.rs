use crate::{
    beacon_chain::BeaconChainTypes,
    summaries_dag::{DAGStateSummaryV22, StateSummariesDAG},
};
use slog::{debug, info, warn, Logger};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    get_full_state_v22, hdiff::StorageStrategy, hot_cold_store::DiffBaseStateRoot, DBColumn, Error,
    HotColdDB, HotStateSummary, KeyValueStore, KeyValueStoreOp, StoreItem,
};
use types::{EthSpec, Hash256, Slot};

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct HotStateSummaryV22 {
    slot: Slot,
    latest_block_root: Hash256,
    epoch_boundary_state_root: Hash256,
}

pub fn upgrade_to_v24<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut migrate_ops = vec![];
    let split = db.get_split_info();
    let hot_hdiff_start_slot = split.slot;

    // Sanity check to make sure the HDiff grid is aligned with the epoch start
    if hot_hdiff_start_slot % T::EthSpec::slots_per_epoch() != 0 {
        return Err(Error::MigrationError(format!(
            "hot_hdiff_start_slot is not first slot in epoch {hot_hdiff_start_slot}"
        )));
    }

    // After V24 hot tree states, the in-memory `anchor_info.anchor_slot` is the start slot of the
    // hot HDiff grid. Before the migration, it's set to the slot of the anchor state in the DB:
    // - the genesis state on a genesis sync, or
    // - the checkpoint state on a checkpoint sync.
    //
    // If the node has been running for a while the `anchor_slot` might be less than the finalized
    // checkpoint. This upgrade constructs a grid only with unfinalized states, rooted in the
    // current finalize state. So we set the `anchor_slot` to `split.slot` to root the grid in the
    // current finalized state. Each migration sets the split to
    // ```
    // Split { slot: finalized_state.slot(), state_root: finalized_state_root }
    // ```
    {
        let anchor_info = db.get_anchor_info();
        let mut new_anchor_info = anchor_info.clone();
        new_anchor_info.anchor_slot = hot_hdiff_start_slot;
        // Update the anchor in disk atomically if migration is successful
        migrate_ops.push(db.compare_and_set_anchor_info(anchor_info, new_anchor_info)?);
    }

    let state_summaries_dag = new_dag::<T>(&db)?;

    // We compute the state summaries DAG outside of a DB migration. Therefore if the DB is properly
    // prunned, it should have a single root equal to the split.
    //
    // TODO(hdiff): To assert this conditions, now we just log warns. We may want to switch to
    // errors later if it can affect correctness when migrating the summaries.
    let state_summaries_dag_roots = state_summaries_dag.tree_roots();
    if state_summaries_dag_roots.len() == 1 {
        let (root_summary_state_root, root_summary) =
            state_summaries_dag_roots.first().expect("len == 1");
        if *root_summary_state_root != split.state_root {
            warn!(
                log,
                "State summaries DAG root is not the split";
                "root_summary_state_root" => ?root_summary_state_root,
                "root_summary" => ?root_summary,
                "split" => ?split,
            );
        }
    } else {
        warn!(
            log,
            "State summaries DAG found more than one root";
            "location" => "migration",
            "state_summaries_dag_roots" => ?state_summaries_dag_roots
        );
    }

    // Sort summaries by slot so we have their ancestor diffs already stored when we store them.
    // If the summaries are sorted topologically we can insert them into the DB like if they were a
    // new state, re-using existing code. As states are likely to be sequential the diff cache
    // should kick in making the migration more efficient. If we just iterate the column of
    // summaries we may get distance state of each iteration.
    let summaries_by_slot = state_summaries_dag.summaries_by_slot_ascending();
    debug!(
        log,
        "Starting hot states migration";
        "summaries_count" => state_summaries_dag.summaries_count(),
        "slots_count" => summaries_by_slot.len(),
        "min_slot" => ?summaries_by_slot.first_key_value().map(|(slot, _)| slot),
        "max_slot" => ?summaries_by_slot.last_key_value().map(|(slot, _)| slot),
        "state_summaries_dag_roots" => ?state_summaries_dag_roots,
        "hot_hdiff_start_slot" => hot_hdiff_start_slot,
        "split_state_root" => ?split.state_root,
    );

    // Upgrade all hot DB state summaries to the new type:
    // - Set all summaries of boundary states as `Snapshot` type
    // - Set all others are `Replay` pointing to `epoch_boundary_state_root`

    let mut diffs_written = 0;
    let mut summaries_written = 0;
    let mut last_log_time = Instant::now();

    for (slot, old_hot_state_summaries) in summaries_by_slot {
        for (state_root, old_summary) in old_hot_state_summaries {
            if slot < hot_hdiff_start_slot {
                // To reach here, there must be some pruning issue with the DB where we still have
                // hot states below the split slot. This states can't be migrated as we can't compute
                // a storage strategy for them. After this if else block, the summary and state are
                // scheduled for deletion.
                debug!(
                    log,
                    "Ignoring state summary prior to split slot";
                    "slot" => slot,
                    "state_root" => ?state_root,
                );
            } else {
                // 1. Store snapshot or diff at this slot (if required).
                let storage_strategy = db.hot_storage_strategy(slot)?;
                debug!(
                    log,
                    "Migrating state summary";
                    "slot" => slot,
                    "state_root" => ?state_root,
                    "storage_strategy" => ?storage_strategy,
                );

                match storage_strategy {
                    StorageStrategy::DiffFrom(_) | StorageStrategy::Snapshot => {
                        // We choose to not compute states during the epoch with block replay for
                        // simplicity. Therefore we can only support a hot heriarchy config where the
                        // lowest layer is >= 5.
                        if slot % T::EthSpec::slots_per_epoch() != 0 {
                            return Err(Error::MigrationError(
                                "Hot hierarchy config lowest value must be >= 5".to_owned(),
                            ));
                        }

                        // Load the full state and re-store it as a snapshot or diff.
                        let state = get_full_state_v22(&db.hot_db, &state_root, &db.spec)?
                            .ok_or(Error::MissingState(state_root))?;

                        // Store immediately so that future diffs can load and diff from it.
                        let mut ops = vec![];
                        // We must commit the hot state summary immediatelly, otherwise we can't diff
                        // against it and future writes will fail. That's why we write the new hot
                        // summaries in a different column to have both new and old data present at
                        // once. Otherwise if the process crashes during the migration the database will
                        // be broken.
                        db.store_hot_state_summary(&state_root, &state, &mut ops)?;
                        db.store_hot_state_diffs(&state_root, &state, &mut ops)?;
                        db.hot_db.do_atomically(ops)?;
                        diffs_written += 1;
                    }
                    StorageStrategy::ReplayFrom(_) => {
                        // Optimization: instead of having to load the state of each summary we load x32
                        // less states by manually computing the HotStateSummary roots using the
                        // computed state dag.
                        //
                        // No need to store diffs for states that will be reconstructed by replaying
                        // blocks.
                        //
                        // 2. Convert the summary to the new format.
                        let previous_state_root = if state_root == split.state_root {
                            Hash256::ZERO
                        } else {
                            state_summaries_dag
                                .previous_state_root(state_root)
                                .map_err(|e| {
                                    Error::MigrationError(format!(
                                        "error computing previous_state_root {e:?}"
                                    ))
                                })?
                        };

                        let diff_base_state_root =
                            if let Some(diff_base_slot) = storage_strategy.diff_base_slot() {
                                DiffBaseStateRoot::new(
                                    diff_base_slot,
                                    state_summaries_dag
                                        .ancestor_state_root_at_slot(state_root, diff_base_slot)
                                        .map_err(|e| {
                                            Error::MigrationError(format!(
                                                "error computing ancestor_state_root_at_slot {e:?}"
                                            ))
                                        })?,
                                )
                            } else {
                                DiffBaseStateRoot::zero()
                            };

                        let new_summary = HotStateSummary {
                            slot,
                            latest_block_root: old_summary.latest_block_root,
                            latest_block_slot: old_summary.latest_block_slot,
                            previous_state_root,
                            diff_base_state_root,
                        };
                        let op = new_summary.as_kv_store_op(state_root);
                        // It's not ncessary to immediately commit the summaries of states that are
                        // ReplayFrom. However we do so for simplicity.
                        db.hot_db.do_atomically(vec![op])?;
                    }
                }
            }

            // 3. Stage old data for deletion.
            if slot % T::EthSpec::slots_per_epoch() == 0 {
                migrate_ops.push(KeyValueStoreOp::DeleteKey(
                    DBColumn::BeaconState,
                    state_root.as_slice().to_vec(),
                ));
            }

            // Delete previous summaries
            migrate_ops.push(KeyValueStoreOp::DeleteKey(
                DBColumn::BeaconStateSummary,
                state_root.as_slice().to_vec(),
            ));

            summaries_written += 1;
            if last_log_time.elapsed() > Duration::from_secs(5) {
                last_log_time = Instant::now();
                info!(
                    log,
                    "Hot states migration in progress";
                    "diffs_written" => diffs_written,
                    "summaries_written" => summaries_written,
                    "summaries_count" => state_summaries_dag.summaries_count(),
                );
            }
        }
    }

    // TODO(hdiff): Should run hot DB compaction after deleting potentially a lot of states. Or should wait
    // for the next finality event?
    info!(
        log,
        "Hot states migration complete";
        "diffs_written" => diffs_written,
        "summaries_written" => summaries_written,
        "summaries_count" => state_summaries_dag.summaries_count(),
    );

    Ok(migrate_ops)
}

pub fn downgrade_from_v24<T: BeaconChainTypes>(
    _db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    _log: Logger,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    panic!("downgrade not supported");
}

fn new_dag<T: BeaconChainTypes>(
    db: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<StateSummariesDAG, Error> {
    // Collect all sumaries for unfinalized states
    let state_summaries_v22 = db
        .hot_db
        // Collect summaries from the legacy V22 column BeaconStateSummary
        .iter_column::<Hash256>(DBColumn::BeaconStateSummary)
        .map(|res| {
            let (key, value) = res?;
            let state_root: Hash256 = key;
            let summary = HotStateSummaryV22::from_ssz_bytes(&value)?;
            let block_root = summary.latest_block_root;
            // Read blocks to get the block slot and parent root. In Holesky forced finalization it
            // took 5100 ms to read 15072 state summaries, so it's not really necessary to
            // de-duplicate block reads.
            let block = db
                .get_blinded_block(&block_root)?
                .ok_or(Error::MissingBlock(block_root))?;

            Ok((
                state_root,
                DAGStateSummaryV22 {
                    slot: summary.slot,
                    latest_block_root: summary.latest_block_root,
                    block_slot: block.slot(),
                    block_parent_root: block.parent_root(),
                },
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    StateSummariesDAG::new_from_v22(state_summaries_v22)
        .map_err(|e| Error::MigrationError(format!("error computing states summaries dag {e:?}")))
}
