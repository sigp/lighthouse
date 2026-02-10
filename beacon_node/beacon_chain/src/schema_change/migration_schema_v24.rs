use crate::{
    beacon_chain::BeaconChainTypes,
    summaries_dag::{DAGStateSummary, DAGStateSummaryV22, StateSummariesDAG},
};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::Encode;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    DBColumn, Error, HotColdDB, HotStateSummary, KeyValueStore, KeyValueStoreOp, StoreItem,
    hdiff::StorageStrategy,
    hot_cold_store::{HotStateSummaryV22, OptionalDiffBaseState},
};
use tracing::{debug, info, warn};
use types::{
    BeaconState, CACHED_EPOCHS, ChainSpec, Checkpoint, CommitteeCache, EthSpec, Hash256, Slot,
};

/// We stopped using the pruning checkpoint in schema v23 but never explicitly deleted it.
///
/// We delete it as part of the v24 migration.
pub const PRUNING_CHECKPOINT_KEY: Hash256 = Hash256::repeat_byte(3);

pub fn store_full_state_v22<E: EthSpec>(
    state_root: &Hash256,
    state: &BeaconState<E>,
    ops: &mut Vec<KeyValueStoreOp>,
) -> Result<(), Error> {
    let bytes = StorageContainer::new(state).as_ssz_bytes();
    ops.push(KeyValueStoreOp::PutKeyValue(
        DBColumn::BeaconState,
        state_root.as_slice().to_vec(),
        bytes,
    ));
    Ok(())
}

/// Fetch a V22 state from the database either as a full state or using block replay.
pub fn get_state_v22<T: BeaconChainTypes>(
    db: &Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    state_root: &Hash256,
    spec: &ChainSpec,
) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
    let Some(summary) = db.get_item::<HotStateSummaryV22>(state_root)? else {
        return Ok(None);
    };
    let Some(base_state) =
        get_full_state_v22(&db.hot_db, &summary.epoch_boundary_state_root, spec)?
    else {
        return Ok(None);
    };
    // Loading hot states via block replay doesn't care about the schema version, so we can use
    // the DB's current method for this.
    let update_cache = false;
    db.load_hot_state_using_replay(
        base_state,
        summary.slot,
        summary.latest_block_root,
        update_cache,
    )
    .map(Some)
}

pub fn get_full_state_v22<KV: KeyValueStore<E>, E: EthSpec>(
    db: &KV,
    state_root: &Hash256,
    spec: &ChainSpec,
) -> Result<Option<BeaconState<E>>, Error> {
    match db.get_bytes(DBColumn::BeaconState, state_root.as_slice())? {
        Some(bytes) => {
            let container = StorageContainer::from_ssz_bytes(&bytes, spec)?;
            Ok(Some(container.try_into()?))
        }
        None => Ok(None),
    }
}

/// A container for storing `BeaconState` components.
///
/// DEPRECATED.
#[derive(Encode)]
pub struct StorageContainer<E: EthSpec> {
    state: BeaconState<E>,
    committee_caches: Vec<Arc<CommitteeCache>>,
}

impl<E: EthSpec> StorageContainer<E> {
    /// Create a new instance for storing a `BeaconState`.
    pub fn new(state: &BeaconState<E>) -> Self {
        Self {
            state: state.clone(),
            committee_caches: state.committee_caches().to_vec(),
        }
    }

    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        // We need to use the slot-switching `from_ssz_bytes` of `BeaconState`, which doesn't
        // compose with the other SSZ utils, so we duplicate some parts of `ssz_derive` here.
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Vec<CommitteeCache>>()?;

        let mut decoder = builder.build()?;

        let state = decoder.decode_next_with(|bytes| BeaconState::from_ssz_bytes(bytes, spec))?;
        let committee_caches = decoder.decode_next()?;

        Ok(Self {
            state,
            committee_caches,
        })
    }
}

impl<E: EthSpec> TryInto<BeaconState<E>> for StorageContainer<E> {
    type Error = Error;

    fn try_into(mut self) -> Result<BeaconState<E>, Error> {
        let mut state = self.state;

        for i in (0..CACHED_EPOCHS).rev() {
            if i >= self.committee_caches.len() {
                return Err(Error::SszDecodeError(DecodeError::BytesInvalid(
                    "Insufficient committees for BeaconState".to_string(),
                )));
            };

            state.committee_caches_mut()[i] = self.committee_caches.remove(i);
        }

        Ok(state)
    }
}

/// The checkpoint used for pruning the database.
///
/// Updated whenever pruning is successful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruningCheckpoint {
    pub checkpoint: Checkpoint,
}

impl StoreItem for PruningCheckpoint {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.checkpoint.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PruningCheckpoint {
            checkpoint: Checkpoint::from_ssz_bytes(bytes)?,
        })
    }
}

pub fn upgrade_to_v24<T: BeaconChainTypes>(
    db: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
) -> Result<Vec<KeyValueStoreOp>, Error> {
    let mut migrate_ops = vec![];
    let split = db.get_split_info();
    let hot_hdiff_start_slot = split.slot;

    // Delete the `PruningCheckpoint` (no longer used).
    migrate_ops.push(KeyValueStoreOp::DeleteKey(
        DBColumn::BeaconMeta,
        PRUNING_CHECKPOINT_KEY.as_slice().to_vec(),
    ));

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
    // current finalized state. So we set the `anchor_slot` to `split.slot` to root the grid in the
    // current finalized state. Each migration sets the split to
    // ```
    // Split { slot: finalized_state.slot(), state_root: finalized_state_root }
    // ```
    {
        let anchor_info = db.get_anchor_info();

        // If the node is already an archive node, we can set the anchor slot to 0 and copy
        // snapshots and diffs from the freezer DB to the hot DB in order to establish an initial
        // hot grid that is aligned/"perfect" (no `start_slot`/`anchor_slot` to worry about).
        //
        // This only works if all of the following are true:
        //
        // - We have the previous snapshot for the split state stored in the freezer DB, i.e.
        //   if `previous_snapshot_slot >= state_upper_limit`.
        // - The split state itself will be stored as a diff or snapshot in the new grid. We choose
        //   not to support a split state that requires block replay, because computing its previous
        //   state root from the DAG is not straight-forward.
        let dummy_start_slot = Slot::new(0);
        let closest_layer_points = db
            .hierarchy
            .closest_layer_points(split.slot, dummy_start_slot);

        let previous_snapshot_slot =
            closest_layer_points
                .iter()
                .copied()
                .min()
                .ok_or(Error::MigrationError(
                    "closest_layer_points must not be empty".to_string(),
                ))?;

        if previous_snapshot_slot >= anchor_info.state_upper_limit
            && db
                .hierarchy
                .storage_strategy(split.slot, dummy_start_slot)
                .is_ok_and(|strategy| !strategy.is_replay_from())
        {
            info!(
                %previous_snapshot_slot,
                split_slot = %split.slot,
                "Aligning hot diff grid to freezer"
            );

            // Set anchor slot to 0 in case it was set to something else by a previous checkpoint
            // sync.
            let mut new_anchor_info = anchor_info.clone();
            new_anchor_info.anchor_slot = Slot::new(0);

            // Update the anchor on disk atomically if migration is successful
            migrate_ops.push(db.compare_and_set_anchor_info(anchor_info, new_anchor_info)?);

            // Copy each of the freezer layers to the hot DB in slot ascending order.
            for layer_slot in closest_layer_points.into_iter().rev() {
                // Do not try to load the split state itself from the freezer, it won't be there.
                // It will be migrated in the main loop below.
                if layer_slot == split.slot {
                    continue;
                }

                let mut freezer_state = db.load_cold_state_by_slot(layer_slot)?;

                let state_root = freezer_state.canonical_root()?;

                let mut state_ops = vec![];
                db.store_hot_state(&state_root, &freezer_state, &mut state_ops)?;
                db.hot_db.do_atomically(state_ops)?;
            }
        } else {
            // Otherwise for non-archive nodes, set the anchor slot for the hot grid to the current
            // split slot (the oldest slot available).
            let mut new_anchor_info = anchor_info.clone();
            new_anchor_info.anchor_slot = hot_hdiff_start_slot;

            // Update the anchor in disk atomically if migration is successful
            migrate_ops.push(db.compare_and_set_anchor_info(anchor_info, new_anchor_info)?);
        }
    }

    let state_summaries_dag = new_dag::<T>(&db)?;

    // We compute the state summaries DAG outside of a DB migration. Therefore if the DB is properly
    // prunned, it should have a single root equal to the split.
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
    // - Set all summaries of boundary states to `Snapshot` type
    // - Set all others to `Replay` pointing to `epoch_boundary_state_root`

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
                        // Load the state and re-store it as a snapshot or diff.
                        let state = get_state_v22::<T>(&db, &state_root, &db.spec)?
                            .ok_or(Error::MissingState(state_root))?;

                        // Store immediately so that future diffs can load and diff from it.
                        let mut ops = vec![];
                        // We must commit the hot state summary immediately, otherwise we can't diff
                        // against it and future writes will fail. That's why we write the new hot
                        // summaries in a different column to have both new and old data present at
                        // once. Otherwise if the process crashes during the migration the database will
                        // be broken.
                        db.store_hot_state_summary(&state_root, &state, &mut ops)?;
                        db.store_hot_state_diffs(&state_root, &state, &mut ops)?;
                        db.hot_db.do_atomically(ops)?;
                        diffs_written += 1;
                    }
                    StorageStrategy::ReplayFrom(diff_base_slot) => {
                        // Optimization: instead of having to load the state of each summary we load x32
                        // less states by manually computing the HotStateSummary roots using the
                        // computed state dag.
                        //
                        // No need to store diffs for states that will be reconstructed by replaying
                        // blocks.
                        //
                        // 2. Convert the summary to the new format.
                        if state_root == split.state_root {
                            return Err(Error::MigrationError(
                                "unreachable: split state should be stored as a snapshot or diff"
                                    .to_string(),
                            ));
                        }
                        let previous_state_root = state_summaries_dag
                            .previous_state_root(state_root)
                            .map_err(|e| {
                                Error::MigrationError(format!(
                                    "error computing previous_state_root {e:?}"
                                ))
                            })?;

                        let diff_base_state = OptionalDiffBaseState::new(
                            diff_base_slot,
                            state_summaries_dag
                                .ancestor_state_root_at_slot(state_root, diff_base_slot)
                                .map_err(|e| {
                                    Error::MigrationError(format!(
                                        "error computing ancestor_state_root_at_slot \
                                         ({state_root:?}, {diff_base_slot}): {e:?}"
                                    ))
                                })?,
                        );

                        let new_summary = HotStateSummary {
                            slot,
                            latest_block_root: old_summary.latest_block_root,
                            latest_block_slot: old_summary.latest_block_slot,
                            previous_state_root,
                            diff_base_state,
                        };
                        let op = new_summary.as_kv_store_op(state_root);
                        // It's not necessary to immediately commit the summaries of states that are
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
    let mut summaries_skipped = 0;
    let mut last_log_time = Instant::now();

    // Rebuild the PruningCheckpoint from the split.
    let split = db.get_split_info();
    let pruning_checkpoint = PruningCheckpoint {
        checkpoint: Checkpoint {
            epoch: split.slot.epoch(T::EthSpec::slots_per_epoch()),
            root: split.block_root,
        },
    };
    migrate_ops.push(pruning_checkpoint.as_kv_store_op(PRUNING_CHECKPOINT_KEY));

    // Convert state summaries back to the old format.
    for (state_root, summary) in state_summaries_dag
        .summaries_by_slot_ascending()
        .into_iter()
        .flat_map(|(_, summaries)| summaries)
    {
        // No need to migrate any states prior to the split. The v22 schema does not need them, and
        // they would generate warnings about a disjoint DAG when re-upgrading to V24.
        if summary.slot < split.slot {
            debug!(
                slot = %summary.slot,
                ?state_root,
                "Skipping migration of pre-split state"
            );
            summaries_skipped += 1;
            continue;
        }

        // If boundary state: persist.
        // Do not cache these states as they are unlikely to be relevant later.
        let update_cache = false;
        if summary.slot % T::EthSpec::slots_per_epoch() == 0 {
            let (state, _) = db
                .load_hot_state(&state_root, update_cache)?
                .ok_or(Error::MissingState(state_root))?;

            // Immediately commit the state, so we don't OOM. It's stored in a different
            // column so if the migration crashes we'll just store extra harmless junk in the DB.
            let mut state_write_ops = vec![];
            store_full_state_v22(&state_root, &state, &mut state_write_ops)?;
            db.hot_db.do_atomically(state_write_ops)?;
            states_written += 1;
        }

        // Persist old summary.
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

    // Delete all V24 schema data. We do this outside the loop over summaries to ensure we cover
    // every piece of data and to simplify logic around skipping certain summaries that do not get
    // migrated.
    for db_column in [
        DBColumn::BeaconStateHotSummary,
        DBColumn::BeaconStateHotDiff,
        DBColumn::BeaconStateHotSnapshot,
    ] {
        for key in db.hot_db.iter_column_keys::<Hash256>(db_column) {
            let state_root = key?;
            migrate_ops.push(KeyValueStoreOp::DeleteKey(
                db_column,
                state_root.as_slice().to_vec(),
            ));
        }
    }

    info!(
        states_written,
        summaries_written,
        summaries_skipped,
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
