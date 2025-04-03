use crate::{
    beacon_chain::BeaconChainTypes,
    summaries_dag::{DAGStateSummary, DAGStateSummaryV22, StateSummariesDAG},
};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    get_full_state_v22, hdiff::StorageStrategy, hot_cold_store::DiffBaseStateRoot,
    store_full_state_v22, DBColumn, Error, HotColdDB, HotStateSummary, KeyValueStore,
    KeyValueStoreOp, StoreItem,
};
use tracing::{debug, info, warn};
use types::{EthSpec, Hash256, Slot};

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct HotStateSummaryV22 {
    slot: Slot,
    latest_block_root: Hash256,
    epoch_boundary_state_root: Hash256,
}

pub fn upgrade_to_v24<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
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
                ?root_summary_state_root,
                ?root_summary,
                ?split,
                "State summaries DAG root is not the split"
            );
        }
    } else {
        warn!(
            location = "migration",
            state_summaries_dag_roots = ?state_summaries_dag_roots,
            "State summaries DAG found more than one root"
        );
    }

    // Sort summaries by slot so we have their ancestor diffs already stored when we store them.
    // If the summaries are sorted topologically we can insert them into the DB like if they were a
    // new state, re-using existing code. As states are likely to be sequential the diff cache
    // should kick in making the migration more efficient. If we just iterate the column of
    // summaries we may get distance state of each iteration.
    let summaries_by_slot = state_summaries_dag.summaries_by_slot_ascending();
    debug!(
        summaries_count = state_summaries_dag.summaries_count(),
        slots_count = summaries_by_slot.len(),
        min_slot = ?summaries_by_slot.first_key_value().map(|(slot, _)| slot),
        max_slot = ?summaries_by_slot.last_key_value().map(|(slot, _)| slot),
        ?state_summaries_dag_roots,
        %hot_hdiff_start_slot,
        split_state_root = ?split.state_root,
        "Starting hot states migration"
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
                    %slot,
                    ?state_root,
                    "Ignoring state summary prior to split slot"
                );
            } else {
                // 1. Store snapshot or diff at this slot (if required).
                let storage_strategy = db.hot_storage_strategy(slot)?;
                debug!(
                    %slot,
                    ?state_root,
                    ?storage_strategy,
                    "Migrating state summary"
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

                        let diff_base_state_root = if let Some(diff_base_slot) =
                            storage_strategy.diff_base_slot()
                        {
                            DiffBaseStateRoot::new(
                                    diff_base_slot,
                                    state_summaries_dag
                                        .ancestor_state_root_at_slot(state_root, diff_base_slot)
                                        .map_err(|e| {
                                            Error::MigrationError(format!(
                                                "error computing ancestor_state_root_at_slot({state_root:?}, {diff_base_slot}) {e:?}"
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
                    diffs_written,
                    summaries_written,
                    summaries_count = state_summaries_dag.summaries_count(),
                    "Hot states migration in progress"
                );
            }
        }
    }

    // TODO(hdiff): Should run hot DB compaction after deleting potentially a lot of states. Or should wait
    // for the next finality event?
    info!(
        diffs_written,
        summaries_written,
        summaries_count = state_summaries_dag.summaries_count(),
        "Hot states migration complete"
    );

    Ok(migrate_ops)
}

pub fn downgrade_from_v24<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let state_summaries = db
        .load_hot_state_summaries()?
        .into_iter()
        .map(|(state_root, summary)| (state_root, summary.into()))
        .collect::<Vec<(Hash256, DAGStateSummary)>>();

    info!(
        summaries_count = state_summaries.len(),
        "DB downgrade of v24 state summaries started"
    );

    let state_summaries_dag = StateSummariesDAG::new(state_summaries)
        .map_err(|e| Error::MigrationError(format!("Error on new StateSumariesDAG {e:?}")))?;

    let mut migrate_ops = vec![];
    let mut states_written = 0;
    let mut summaries_written = 0;
    let mut last_log_time = Instant::now();

    // TODO(tree-states): What about the anchor_slot? Is it safe to run the prior version of
    // Lighthouse with an a higher anchor_slot than expected?

    for (state_root, summary) in state_summaries_dag
        .summaries_by_slot_ascending()
        .into_iter()
        .flat_map(|(_, summaries)| summaries)
    {
        // If boundary state persist
        if summary.slot % T::EthSpec::slots_per_epoch() == 0 {
            let (state, _) = db
                .load_hot_state(&state_root)?
                .ok_or(Error::MissingState(state_root))?;

            // Immediately commit the state. Otherwise we will OOM and it's stored in a different
            // column. So if the migration crashes we just get extra harmless junk in the DB.
            let mut state_write_ops = vec![];
            store_full_state_v22(&state_root, &state, &mut state_write_ops)?;
            db.hot_db.do_atomically(state_write_ops)?;
            states_written += 1;
        }

        // Persist old summary
        let epoch_boundary_state_slot = summary.slot - summary.slot % T::EthSpec::slots_per_epoch();
        let old_summary = HotStateSummaryV22 {
            slot: summary.slot,
            latest_block_root: summary.latest_block_root,
            epoch_boundary_state_root: state_summaries_dag
                .ancestor_state_root_at_slot(state_root, epoch_boundary_state_slot)
                .map_err(|e| {
                    Error::MigrationError(format!(
                        "error computing ancestor_state_root_at_slot({state_root:?}, {epoch_boundary_state_slot}) {e:?}"
                    ))
                })?,
        };
        migrate_ops.push(KeyValueStoreOp::PutKeyValue(
            DBColumn::BeaconStateSummary,
            state_root.as_slice().to_vec(),
            old_summary.as_ssz_bytes(),
        ));
        summaries_written += 1;

        // Delete existing data
        for db_column in [
            DBColumn::BeaconStateHotSummary,
            DBColumn::BeaconStateHotDiff,
            DBColumn::BeaconStateHotSnapshot,
        ] {
            migrate_ops.push(KeyValueStoreOp::DeleteKey(
                db_column,
                state_root.as_slice().to_vec(),
            ));
        }

        if last_log_time.elapsed() > Duration::from_secs(5) {
            last_log_time = Instant::now();
            info!(
                states_written,
                summaries_written,
                summaries_count = state_summaries_dag.summaries_count(),
                "DB downgrade of v24 state summaries in progress"
            );
        }
    }

    info!(
        states_written,
        summaries_written,
        summaries_count = state_summaries_dag.summaries_count(),
        "DB downgrade of v24 state summaries completed"
    );

    Ok(migrate_ops)
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
