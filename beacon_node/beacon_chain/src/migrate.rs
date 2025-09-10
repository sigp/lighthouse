use crate::errors::BeaconChainError;
use crate::summaries_dag::{DAGStateSummary, Error as SummariesDagError, StateSummariesDAG};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::mem;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::hot_cold_store::{HotColdDBError, migrate_database};
use store::{Error, ItemStore, Split, StoreOp};
pub use store::{HotColdDB, MemoryStore};
use tracing::{debug, error, info, warn};
use types::{BeaconState, BeaconStateHash, Checkpoint, Epoch, EthSpec, Hash256, Slot};

/// Compact at least this frequently, finalization permitting (7 days).
const MAX_COMPACTION_PERIOD_SECONDS: u64 = 604800;
/// Compact at *most* this frequently, to prevent over-compaction during sync (2 hours).
const MIN_COMPACTION_PERIOD_SECONDS: u64 = 7200;
/// Compact after a large finality gap, if we respect `MIN_COMPACTION_PERIOD_SECONDS`.
const COMPACTION_FINALITY_DISTANCE: u64 = 1024;
/// Maximum number of blocks applied in each reconstruction burst.
///
/// This limits the amount of time that the finalization migration is paused for. We set this
/// conservatively because pausing the finalization migration for too long can cause hot state
/// cache misses and excessive disk use.
const BLOCKS_PER_RECONSTRUCTION: usize = 1024;

/// Default number of epochs to wait between finalization migrations.
pub const DEFAULT_EPOCHS_PER_MIGRATION: u64 = 1;

/// The background migrator runs a thread to perform pruning and migrate state from the hot
/// to the cold database.
pub struct BackgroundMigrator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    db: Arc<HotColdDB<E, Hot, Cold>>,
    /// Record of when the last migration ran, for enforcing `epochs_per_migration`.
    prev_migration: Arc<Mutex<PrevMigration>>,
    #[allow(clippy::type_complexity)]
    tx_thread: Option<Mutex<(mpsc::Sender<Notification>, thread::JoinHandle<()>)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigratorConfig {
    pub blocking: bool,
    /// Run migrations at most once per `epochs_per_migration`.
    ///
    /// If set to 0 or 1, then run every finalization.
    pub epochs_per_migration: u64,
}

impl Default for MigratorConfig {
    fn default() -> Self {
        Self {
            blocking: false,
            epochs_per_migration: DEFAULT_EPOCHS_PER_MIGRATION,
        }
    }
}

impl MigratorConfig {
    pub fn blocking(mut self) -> Self {
        self.blocking = true;
        self
    }

    pub fn epochs_per_migration(mut self, epochs_per_migration: u64) -> Self {
        self.epochs_per_migration = epochs_per_migration;
        self
    }
}

/// Record of when the last migration ran.
pub struct PrevMigration {
    /// The epoch at which the last finalization migration ran.
    epoch: Epoch,
    /// The number of epochs to wait between runs.
    epochs_per_migration: u64,
}

/// Pruning can be successful, or in rare cases deferred to a later point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruningOutcome {
    /// The pruning succeeded and updated the pruning checkpoint from `old_finalized_checkpoint`.
    Successful {
        old_finalized_checkpoint_epoch: Epoch,
    },
    /// The run was aborted because the new finalized checkpoint is older than the previous one.
    OutOfOrderFinalization {
        old_finalized_checkpoint: Checkpoint,
        new_finalized_checkpoint: Checkpoint,
    },
    /// The run was aborted due to a concurrent mutation of the head tracker.
    DeferredConcurrentHeadTrackerMutation,
}

/// Logic errors that can occur during pruning, none of these should ever happen.
#[derive(Debug)]
pub enum PruningError {
    IncorrectFinalizedState {
        state_slot: Slot,
        new_finalized_slot: Slot,
    },
    MissingInfoForCanonicalChain {
        slot: Slot,
    },
    FinalizedStateOutOfOrder {
        old_finalized_checkpoint: Checkpoint,
        new_finalized_checkpoint: Checkpoint,
    },
    UnexpectedEqualStateRoots,
    UnexpectedUnequalStateRoots,
    MissingSummaryForFinalizedCheckpoint(Hash256),
    MissingBlindedBlock(Hash256),
    SummariesDagError(&'static str, SummariesDagError),
    EmptyFinalizedStates,
    EmptyFinalizedBlocks,
}

/// Message sent to the migration thread containing the information it needs to run.
pub enum Notification {
    Finalization(FinalizationNotification),
    Reconstruction,
    PruneBlobs(Epoch),
    ManualFinalization(ManualFinalizationNotification),
    ManualCompaction,
}

pub struct ManualFinalizationNotification {
    pub state_root: BeaconStateHash,
    pub checkpoint: Checkpoint,
}

pub struct FinalizationNotification {
    pub finalized_state_root: BeaconStateHash,
    pub finalized_checkpoint: Checkpoint,
    pub prev_migration: Arc<Mutex<PrevMigration>>,
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> BackgroundMigrator<E, Hot, Cold> {
    /// Create a new `BackgroundMigrator` and spawn its thread if necessary.
    pub fn new(db: Arc<HotColdDB<E, Hot, Cold>>, config: MigratorConfig) -> Self {
        // Estimate last migration run from DB split slot.
        let prev_migration = Arc::new(Mutex::new(PrevMigration {
            epoch: db.get_split_slot().epoch(E::slots_per_epoch()),
            epochs_per_migration: config.epochs_per_migration,
        }));
        let tx_thread = if config.blocking {
            None
        } else {
            Some(Mutex::new(Self::spawn_thread(db.clone())))
        };
        Self {
            db,
            tx_thread,
            prev_migration,
        }
    }

    /// Process a finalized checkpoint from the `BeaconChain`.
    ///
    /// If successful, all forks descending from before the `finalized_checkpoint` will be
    /// pruned, and the split point of the database will be advanced to the slot of the finalized
    /// checkpoint.
    pub fn process_finalization(
        &self,
        finalized_state_root: BeaconStateHash,
        finalized_checkpoint: Checkpoint,
    ) -> Result<(), BeaconChainError> {
        let notif = FinalizationNotification {
            finalized_state_root,
            finalized_checkpoint,
            prev_migration: self.prev_migration.clone(),
        };

        // Send to background thread if configured, otherwise run in foreground.
        if let Some(Notification::Finalization(notif)) =
            self.send_background_notification(Notification::Finalization(notif))
        {
            Self::run_migration(self.db.clone(), notif);
        }

        Ok(())
    }

    pub fn process_manual_compaction(&self) {
        if let Some(Notification::ManualCompaction) =
            self.send_background_notification(Notification::ManualCompaction)
        {
            Self::run_manual_compaction(self.db.clone());
        }
    }

    pub fn process_manual_finalization(&self, notif: ManualFinalizationNotification) {
        if let Some(Notification::ManualFinalization(notif)) =
            self.send_background_notification(Notification::ManualFinalization(notif))
        {
            Self::run_manual_migration(self.db.clone(), notif);
        }
    }

    pub fn process_reconstruction(&self) {
        if let Some(Notification::Reconstruction) =
            self.send_background_notification(Notification::Reconstruction)
        {
            // If we are running in foreground mode (as in tests), then this will just run a single
            // batch. We may need to tweak this in future.
            Self::run_reconstruction(self.db.clone(), None);
        }
    }

    pub fn process_prune_blobs(&self, data_availability_boundary: Epoch) {
        if let Some(Notification::PruneBlobs(data_availability_boundary)) =
            self.send_background_notification(Notification::PruneBlobs(data_availability_boundary))
        {
            Self::run_prune_blobs(self.db.clone(), data_availability_boundary);
        }
    }

    pub fn run_reconstruction(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        opt_tx: Option<mpsc::Sender<Notification>>,
    ) {
        match db.reconstruct_historic_states(Some(BLOCKS_PER_RECONSTRUCTION)) {
            Ok(()) => {
                // Schedule another reconstruction batch if required and we have access to the
                // channel for requeueing.
                if let Some(tx) = opt_tx
                    && !db.get_anchor_info().all_historic_states_stored()
                    && let Err(e) = tx.send(Notification::Reconstruction)
                {
                    error!(
                        error = ?e,
                        "Unable to requeue reconstruction notification"
                    );
                }
            }
            Err(e) => {
                error!(
                    error = ?e,
                    "State reconstruction failed"
                );
            }
        }
    }

    pub fn run_prune_blobs(db: Arc<HotColdDB<E, Hot, Cold>>, data_availability_boundary: Epoch) {
        if let Err(e) = db.try_prune_blobs(false, data_availability_boundary) {
            error!(
                error = ?e,
                "Blob pruning failed"
            );
        }
    }

    /// If configured to run in the background, send `notif` to the background thread.
    ///
    /// Return `None` if the message was sent to the background thread, `Some(notif)` otherwise.
    #[must_use = "Message is not processed when this function returns `Some`"]
    fn send_background_notification(&self, notif: Notification) -> Option<Notification> {
        // Async path, on the background thread.
        if let Some(tx_thread) = &self.tx_thread {
            let (ref mut tx, ref mut thread) = *tx_thread.lock();

            // Restart the background thread if it has crashed.
            if let Err(tx_err) = tx.send(notif) {
                let (new_tx, new_thread) = Self::spawn_thread(self.db.clone());

                *tx = new_tx;
                let old_thread = mem::replace(thread, new_thread);

                // Join the old thread, which will probably have panicked, or may have
                // halted normally just now as a result of us dropping the old `mpsc::Sender`.
                if let Err(thread_err) = old_thread.join() {
                    warn!(
                        reason = ?thread_err,
                        "Migration thread died, so it was restarted"
                    );
                }

                // Retry at most once, we could recurse but that would risk overflowing the stack.
                let _ = tx.send(tx_err.0);
            }
            None
        // Synchronous path, on the current thread.
        } else {
            Some(notif)
        }
    }

    fn run_manual_migration(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        notif: ManualFinalizationNotification,
    ) {
        // We create a "dummy" prev migration
        let prev_migration = PrevMigration {
            epoch: Epoch::new(1),
            epochs_per_migration: 2,
        };
        let notif = FinalizationNotification {
            finalized_state_root: notif.state_root,
            finalized_checkpoint: notif.checkpoint,
            prev_migration: Arc::new(prev_migration.into()),
        };
        Self::run_migration(db, notif);
    }

    /// Perform the actual work of `process_finalization`.
    fn run_migration(db: Arc<HotColdDB<E, Hot, Cold>>, notif: FinalizationNotification) {
        // Do not run too frequently.
        let epoch = notif.finalized_checkpoint.epoch;
        let mut prev_migration = notif.prev_migration.lock();
        if epoch < prev_migration.epoch + prev_migration.epochs_per_migration {
            debug!(
                last_finalized_epoch = %prev_migration.epoch,
                new_finalized_epoch = %epoch,
                epochs_per_migration = prev_migration.epochs_per_migration,
                "Database consolidation deferred"
            );
            return;
        }

        // Update the previous migration epoch immediately to avoid holding the lock. If the
        // migration doesn't succeed then the next migration will be retried at the next scheduled
        // run.
        prev_migration.epoch = epoch;
        drop(prev_migration);

        debug!("Database consolidation started");

        let finalized_state_root = notif.finalized_state_root;
        let finalized_block_root = notif.finalized_checkpoint.root;

        // The enshrined finalized state should be in the state cache.
        let finalized_state = match db.get_state(&finalized_state_root.into(), None, true) {
            Ok(Some(state)) => state,
            other => {
                error!(
                    state_root = ?finalized_state_root,
                    error = ?other,
                    "Migrator failed to load state"
                );
                return;
            }
        };

        let split_prior_to_migration = match migrate_database(
            db.clone(),
            finalized_state_root.into(),
            finalized_block_root,
            &finalized_state,
        ) {
            Ok(split_change) => {
                // Migration run, return the split before the migration
                split_change.previous
            }
            Err(Error::HotColdDBError(HotColdDBError::FreezeSlotUnaligned(slot))) => {
                debug!(
                    slot = slot.as_u64(),
                    "Database migration postponed, unaligned finalized block"
                );
                // Migration did not run, return the current split info
                db.get_split_info()
            }
            Err(e) => {
                warn!(error = ?e, "Database migration failed");
                return;
            }
        };

        let old_finalized_checkpoint_epoch = match Self::prune_hot_db(
            db.clone(),
            finalized_state_root.into(),
            &finalized_state,
            notif.finalized_checkpoint,
            split_prior_to_migration,
        ) {
            Ok(PruningOutcome::Successful {
                old_finalized_checkpoint_epoch,
            }) => old_finalized_checkpoint_epoch,
            Ok(PruningOutcome::DeferredConcurrentHeadTrackerMutation) => {
                warn!(
                    message = "this is expected only very rarely!",
                    "Pruning deferred because of a concurrent mutation"
                );
                return;
            }
            Ok(PruningOutcome::OutOfOrderFinalization {
                old_finalized_checkpoint,
                new_finalized_checkpoint,
            }) => {
                warn!(
                    old_finalized_epoch = %old_finalized_checkpoint.epoch,
                    new_finalized_epoch = %new_finalized_checkpoint.epoch,
                    message = "this is expected occasionally due to a (harmless) race condition",
                    "Ignoring out of order finalization request"
                );
                return;
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    "Hot DB pruning failed"
                );
                return;
            }
        };

        // Finally, compact the database so that new free space is properly reclaimed.
        if let Err(e) = Self::run_compaction(
            db,
            old_finalized_checkpoint_epoch,
            notif.finalized_checkpoint.epoch,
        ) {
            warn!(error = ?e, "Database compaction failed");
        }

        debug!("Database consolidation complete");
    }

    fn run_manual_compaction(db: Arc<HotColdDB<E, Hot, Cold>>) {
        debug!("Running manual compaction");
        if let Err(error) = db.compact() {
            warn!(?error, "Database compaction failed");
        } else {
            debug!("Manual compaction completed");
        }
    }

    /// Spawn a new child thread to run the migration process.
    ///
    /// Return a channel handle for sending requests to the thread.
    fn spawn_thread(
        db: Arc<HotColdDB<E, Hot, Cold>>,
    ) -> (mpsc::Sender<Notification>, thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let inner_tx = tx.clone();
        let thread = thread::spawn(move || {
            while let Ok(notif) = rx.recv() {
                let mut reconstruction_notif = None;
                let mut finalization_notif = None;
                let mut manual_finalization_notif = None;
                let mut manual_compaction_notif = None;
                let mut prune_blobs_notif = None;
                match notif {
                    Notification::Reconstruction => reconstruction_notif = Some(notif),
                    Notification::Finalization(fin) => finalization_notif = Some(fin),
                    Notification::ManualFinalization(fin) => manual_finalization_notif = Some(fin),
                    Notification::PruneBlobs(dab) => prune_blobs_notif = Some(dab),
                    Notification::ManualCompaction => manual_compaction_notif = Some(notif),
                }
                // Read the rest of the messages in the channel, taking the best of each type.
                for notif in rx.try_iter() {
                    match notif {
                        Notification::Reconstruction => reconstruction_notif = Some(notif),
                        Notification::ManualCompaction => manual_compaction_notif = Some(notif),
                        Notification::ManualFinalization(fin) => {
                            if let Some(current) = manual_finalization_notif.as_mut() {
                                if fin.checkpoint.epoch > current.checkpoint.epoch {
                                    *current = fin;
                                }
                            } else {
                                manual_finalization_notif = Some(fin);
                            }
                        }
                        Notification::Finalization(fin) => {
                            if let Some(current) = finalization_notif.as_mut() {
                                if fin.finalized_checkpoint.epoch
                                    > current.finalized_checkpoint.epoch
                                {
                                    *current = fin;
                                }
                            } else {
                                finalization_notif = Some(fin);
                            }
                        }
                        Notification::PruneBlobs(dab) => {
                            prune_blobs_notif = std::cmp::max(prune_blobs_notif, Some(dab));
                        }
                    }
                }
                // Run finalization and blob pruning migrations first, then a reconstruction batch.
                // This prevents finalization from being starved while reconstruciton runs (a
                // problem in previous LH versions).
                if let Some(fin) = finalization_notif {
                    Self::run_migration(db.clone(), fin);
                }
                if let Some(fin) = manual_finalization_notif {
                    Self::run_manual_migration(db.clone(), fin);
                }
                if let Some(dab) = prune_blobs_notif {
                    Self::run_prune_blobs(db.clone(), dab);
                }
                if reconstruction_notif.is_some() {
                    Self::run_reconstruction(db.clone(), Some(inner_tx.clone()));
                }
                if manual_compaction_notif.is_some() {
                    Self::run_manual_compaction(db.clone());
                }
            }
        });
        (tx, thread)
    }

    /// Traverses live heads and prunes blocks and states of chains that we know can't be built
    /// upon because finalization would prohibit it. This is an optimisation intended to save disk
    /// space.
    fn prune_hot_db(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        new_finalized_state_root: Hash256,
        new_finalized_state: &BeaconState<E>,
        new_finalized_checkpoint: Checkpoint,
        split_prior_to_migration: Split,
    ) -> Result<PruningOutcome, BeaconChainError> {
        let new_finalized_slot = new_finalized_checkpoint
            .epoch
            .start_slot(E::slots_per_epoch());

        // The finalized state must be for the epoch boundary slot, not the slot of the finalized
        // block.
        if new_finalized_state.slot() != new_finalized_slot {
            return Err(PruningError::IncorrectFinalizedState {
                state_slot: new_finalized_state.slot(),
                new_finalized_slot,
            }
            .into());
        }

        debug!(
            split_prior_to_migration = ?split_prior_to_migration,
            new_finalized_checkpoint = ?new_finalized_checkpoint,
            new_finalized_state_root = %new_finalized_state_root,
            "Starting database pruning"
        );

        let state_summaries_dag = {
            let state_summaries = store
                .load_hot_state_summaries()?
                .into_iter()
                .map(|(state_root, summary)| (state_root, summary.into()))
                .collect::<Vec<(Hash256, DAGStateSummary)>>();

            // Sanity check, there is at least one summary with the new finalized block root
            if !state_summaries
                .iter()
                .any(|(_, s)| s.latest_block_root == new_finalized_checkpoint.root)
            {
                return Err(BeaconChainError::PruningError(
                    PruningError::MissingSummaryForFinalizedCheckpoint(
                        new_finalized_checkpoint.root,
                    ),
                ));
            }

            StateSummariesDAG::new(state_summaries)
                .map_err(|e| PruningError::SummariesDagError("new StateSumariesDAG", e))?
        };

        // To debug faulty trees log if we unexpectedly have more than one root. These trees may not
        // result in an error, as they may not be queried in the codepaths below.
        let state_summaries_dag_roots = state_summaries_dag.tree_roots();
        let state_summaries_dag_roots_post_split = state_summaries_dag_roots
            .iter()
            .filter(|(_, s)| s.slot >= split_prior_to_migration.slot)
            .collect::<Vec<_>>();

        // Because of the additional HDiffs kept for the grid prior to finalization the tree_roots
        // function will consider them roots. Those are expected. We just want to assert that the
        // relevant tree of states (post-split) is well-formed.
        //
        // This warning could also fire if we have imported a block that doesn't descend from the
        // new finalized state, and has had its ancestor state summaries pruned by a previous
        // run. See: https://github.com/sigp/lighthouse/issues/7270.
        if state_summaries_dag_roots_post_split.len() > 1 {
            warn!(
                location = "pruning",
                new_finalized_state_root = ?new_finalized_state_root,
                split_prior_to_migration_slot = %split_prior_to_migration.slot,
                state_summaries_dag_roots_post_split = ?state_summaries_dag_roots_post_split,
                error = "summaries dag found more than one root",
                "Notify the devs your hot DB has some inconsistency. Pruning will fix it but devs want to know about it",
            );
        }

        // `new_finalized_state_root` is the *state at the slot of the finalized epoch*,
        // rather than the state of the latest finalized block. These two values will only
        // differ when the first slot of the finalized epoch is a skip slot.
        let finalized_and_descendant_state_roots_of_finalized_checkpoint =
            HashSet::<Hash256>::from_iter(
                std::iter::once(new_finalized_state_root).chain(
                    state_summaries_dag
                        .descendants_of(&new_finalized_state_root)
                        .map_err(|e| PruningError::SummariesDagError("descendants of", e))?,
                ),
            );

        // Collect all `latest_block_roots` of the
        // finalized_and_descendant_state_roots_of_finalized_checkpoint set. Includes the finalized
        // block as `new_finalized_state_root` always has a latest block root equal to the finalized
        // block.
        let finalized_and_descendant_block_roots_of_finalized_checkpoint =
            HashSet::<Hash256>::from_iter(
                state_summaries_dag
                    .blocks_of_states(
                        finalized_and_descendant_state_roots_of_finalized_checkpoint.iter(),
                    )
                    // should never error, we just constructed
                    // finalized_and_descendant_state_roots_of_finalized_checkpoint from the
                    // state_summaries_dag
                    .map_err(|e| PruningError::SummariesDagError("blocks of descendant", e))?
                    .into_iter()
                    .map(|(block_root, _)| block_root),
            );

        // Note: ancestors_of includes the finalized state root
        let newly_finalized_state_summaries = state_summaries_dag
            .ancestors_of(new_finalized_state_root)
            .map_err(|e| PruningError::SummariesDagError("ancestors of", e))?;
        let newly_finalized_state_roots = newly_finalized_state_summaries
            .iter()
            .map(|(root, _)| *root)
            .collect::<HashSet<Hash256>>();
        let newly_finalized_states_min_slot = *newly_finalized_state_summaries
            .iter()
            .map(|(_, slot)| slot)
            .min()
            .ok_or(PruningError::EmptyFinalizedStates)?;

        // Note: ancestors_of includes the finalized block
        let newly_finalized_blocks = state_summaries_dag
            .blocks_of_states(newly_finalized_state_roots.iter())
            .map_err(|e| PruningError::SummariesDagError("blocks of newly finalized", e))?;

        // Compute the set of finalized state roots that we must keep to make the dynamic HDiff system
        // work.
        let required_finalized_diff_state_slots = store
            .hierarchy
            .closest_layer_points(new_finalized_slot, store.hot_hdiff_start_slot()?);

        // We don't know which blocks are shared among abandoned chains, so we buffer and delete
        // everything in one fell swoop.
        let mut blocks_to_prune: HashSet<Hash256> = HashSet::new();
        let mut states_to_prune: HashSet<(Slot, Hash256)> = HashSet::new();
        let mut kept_summaries_for_hdiff = vec![];

        // Consider the following block tree where we finalize block `[0]` at the checkpoint `(f)`.
        // There's a block `[3]` that descendends from the finalized block but NOT from the
        // finalized checkpoint. The block tree rooted in `[3]` conflicts with finality and must be
        // pruned. Therefore we collect all state summaries descendant of `(f)`.
        //
        //           finalize epoch boundary
        //           |    /-------[2]-----
        // [0]-------|--(f)--[1]----------
        //  \---[3]--|-----------------[4]
        //           |

        for (_, summaries) in state_summaries_dag.summaries_by_slot_ascending() {
            for (state_root, summary) in summaries {
                let should_prune = if finalized_and_descendant_state_roots_of_finalized_checkpoint
                    .contains(&state_root)
                {
                    // This state is a viable descendant of the finalized checkpoint, so does not
                    // conflict with finality and can be built on or become a head
                    false
                } else if required_finalized_diff_state_slots.contains(&summary.slot) {
                    // Keep this state and diff as it's necessary for the finalized portion of the
                    // HDiff links. `required_finalized_diff_state_slots` tracks the set of slots on
                    // each diff layer, and by checking `newly_finalized_state_roots` which only
                    // keep those on the finalized canonical chain. Checking the state root ensures
                    // we avoid lingering forks.

                    // In the diagram below, `o` are diffs by slot that we must keep. In the prior
                    // finalized section there's only one chain so we preserve them unconditionally.
                    // For the newly finalized chain, we check which of these is canonical and only
                    // keep those. Slots below `min_finalized_state_slot` we don't have canonical
                    // information so we assume they are part of the finalized pruned chain.
                    //
                    //                  /-----o----
                    // o-------o------/-------o----
                    if summary.slot < newly_finalized_states_min_slot
                        || newly_finalized_state_roots.contains(&state_root)
                    {
                        // Track kept summaries to debug hdiff inconsistencies with "Extra pruning information"
                        kept_summaries_for_hdiff.push((state_root, summary.slot));
                        false
                    } else {
                        true
                    }
                } else {
                    // Everything else, prune
                    true
                };

                if should_prune {
                    // States are migrated into the cold DB in the migrate step. All hot states
                    // prior to finalized can be pruned from the hot DB columns
                    states_to_prune.insert((summary.slot, state_root));
                }
            }
        }

        for (block_root, slot) in state_summaries_dag.iter_blocks() {
            // Blocks both finalized and unfinalized are in the same DB column. We must only
            // prune blocks from abandoned forks. Note that block pruning and state pruning differ.
            // The blocks DB column is shared for hot and cold data, while the states have different
            // columns. Thus, we only prune unviable blocks or from abandoned forks.
            let should_prune = if finalized_and_descendant_block_roots_of_finalized_checkpoint
                .contains(&block_root)
            {
                // Keep unfinalized blocks descendant of finalized checkpoint + finalized block
                // itself Note that we anchor this set on the finalized checkpoint instead of the
                // finalized block. A diagram above shows a relevant example.
                false
            } else if newly_finalized_blocks.contains(&(block_root, slot)) {
                // Keep recently finalized blocks
                false
            } else if slot < newly_finalized_states_min_slot {
                // Keep recently finalized blocks that we know are canonical. Blocks with slots <
                // that `newly_finalized_blocks_min_slot` we don't have canonical information so we
                // assume they are part of the finalized pruned chain
                //
                // Pruning these would risk breaking the DB by deleting canonical blocks once the
                // HDiff grid advances. If the pruning routine is correct this condition should
                // never be hit.
                false
            } else {
                // Everything else, prune
                true
            };

            if should_prune {
                blocks_to_prune.insert(block_root);
            }
        }

        // Sort states to prune to make it more readable
        let mut states_to_prune = states_to_prune.into_iter().collect::<Vec<_>>();
        states_to_prune.sort_by_key(|(slot, _)| *slot);

        debug!(
            new_finalized_checkpoint = ?new_finalized_checkpoint,
            new_finalized_state_root = ?new_finalized_state_root,
            split_prior_to_migration = ?split_prior_to_migration,
            newly_finalized_blocks = newly_finalized_blocks.len(),
            newly_finalized_state_roots = newly_finalized_state_roots.len(),
            newly_finalized_states_min_slot = %newly_finalized_states_min_slot,
            required_finalized_diff_state_slots = ?required_finalized_diff_state_slots,
            kept_summaries_for_hdiff = ?kept_summaries_for_hdiff,
            state_summaries_count = state_summaries_dag.summaries_count(),
            state_summaries_dag_roots = ?state_summaries_dag_roots,
            finalized_and_descendant_state_roots_of_finalized_checkpoint = finalized_and_descendant_state_roots_of_finalized_checkpoint.len(),
            blocks_to_prune = blocks_to_prune.len(),
            states_to_prune = states_to_prune.len(),
            "Extra pruning information"
        );
        // Don't log the full `states_to_prune` in the log statement above as it can result in a
        // single log line of +1Kb and break logging setups. Log `new_finalized_state_root` as a
        // prunning ID to trace these individual logs to the above "Extra pruning information"
        for block_root in &blocks_to_prune {
            debug!(?new_finalized_state_root, ?block_root, "Pruning block");
        }
        for (slot, state_root) in &states_to_prune {
            debug!(
                ?new_finalized_state_root,
                ?state_root,
                %slot,
                "Pruning hot state"
            );
        }

        let mut batch: Vec<StoreOp<E>> = blocks_to_prune
            .into_iter()
            .flat_map(|block_root| {
                [
                    StoreOp::DeleteBlock(block_root),
                    StoreOp::DeleteExecutionPayload(block_root),
                    StoreOp::DeleteBlobs(block_root),
                    StoreOp::DeleteSyncCommitteeBranch(block_root),
                ]
            })
            .chain(states_to_prune.into_iter().flat_map(|(slot, state_hash)| {
                // Hot state diffs necessary for the HDiff grid are never added to `states_to_prune`
                [StoreOp::DeleteState(state_hash, Some(slot))]
            }))
            .collect();

        // Prune sync committee branches of non-checkpoint canonical finalized blocks
        Self::prune_non_checkpoint_sync_committee_branches(&newly_finalized_blocks, &mut batch);

        // Prune all payloads of the canonical finalized blocks
        if store.get_config().prune_payloads {
            Self::prune_finalized_payloads(new_finalized_slot, &newly_finalized_blocks, &mut batch);
        }

        store.do_atomically_with_block_and_blobs_cache(batch)?;

        debug!(?new_finalized_state_root, "Database pruning complete");

        Ok(PruningOutcome::Successful {
            // Approximation of the previous finalized checkpoint. Only used in the compaction to
            // compute time since last compaction.
            old_finalized_checkpoint_epoch: newly_finalized_states_min_slot
                .epoch(E::slots_per_epoch()),
        })
    }

    fn prune_finalized_payloads(
        new_finalized_slot: Slot,
        finalized_blocks: &[(Hash256, Slot)],
        hot_db_ops: &mut Vec<StoreOp<E>>,
    ) {
        for (block_root, slot) in finalized_blocks {
            // Delete the execution payload if payload pruning is enabled. At a skipped slot we may
            // delete the payload for the finalized block itself, but that's OK as we only guarantee
            // that payloads are present for slots >= the split slot.
            if *slot < new_finalized_slot {
                hot_db_ops.push(StoreOp::DeleteExecutionPayload(*block_root));
            }
        }
    }

    fn prune_non_checkpoint_sync_committee_branches(
        finalized_blocks_desc: &[(Hash256, Slot)],
        hot_db_ops: &mut Vec<StoreOp<E>>,
    ) {
        let mut epoch_boundary_blocks = HashSet::new();
        let mut non_checkpoint_block_roots = HashSet::new();

        // Then, iterate states in slot ascending order, as they are stored wrt previous states.
        for (block_root, slot) in finalized_blocks_desc.iter().rev() {
            // At a missed slot, `state_root_iter` will return the block root
            // from the previous non-missed slot. This ensures that the block root at an
            // epoch boundary is always a checkpoint block root. We keep track of block roots
            // at epoch boundaries by storing them in the `epoch_boundary_blocks` hash set.
            // We then ensure that block roots at the epoch boundary aren't included in the
            // `non_checkpoint_block_roots` hash set.
            if *slot % E::slots_per_epoch() == 0 {
                epoch_boundary_blocks.insert(block_root);
            } else {
                non_checkpoint_block_roots.insert(block_root);
            }

            if epoch_boundary_blocks.contains(&block_root) {
                non_checkpoint_block_roots.remove(&block_root);
            }
        }

        // Prune sync committee branch data for all non checkpoint block roots.
        // Note that `non_checkpoint_block_roots` should only contain non checkpoint block roots
        // as long as `finalized_state.slot()` is at an epoch boundary. If this were not the case
        // we risk the chance of pruning a `sync_committee_branch` for a checkpoint block root.
        // E.g. if `current_split_slot` = (Epoch A slot 0) and `finalized_state.slot()` = (Epoch C slot 31)
        // and (Epoch D slot 0) is a skipped slot, we will have pruned a `sync_committee_branch`
        // for a checkpoint block root.
        non_checkpoint_block_roots
            .into_iter()
            .for_each(|block_root| {
                hot_db_ops.push(StoreOp::DeleteSyncCommitteeBranch(*block_root));
            });
    }

    /// Compact the database if it has been more than `COMPACTION_PERIOD_SECONDS` since it
    /// was last compacted.
    pub fn run_compaction(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        old_finalized_epoch: Epoch,
        new_finalized_epoch: Epoch,
    ) -> Result<(), Error> {
        if !db.compact_on_prune() {
            return Ok(());
        }

        let last_compaction_timestamp = db
            .load_compaction_timestamp()?
            .unwrap_or_else(|| Duration::from_secs(0));
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(last_compaction_timestamp);
        let seconds_since_last_compaction = start_time
            .checked_sub(last_compaction_timestamp)
            .as_ref()
            .map_or(0, Duration::as_secs);

        if seconds_since_last_compaction > MAX_COMPACTION_PERIOD_SECONDS
            || (new_finalized_epoch - old_finalized_epoch > COMPACTION_FINALITY_DISTANCE
                && seconds_since_last_compaction > MIN_COMPACTION_PERIOD_SECONDS)
        {
            info!(
                %old_finalized_epoch,
                %new_finalized_epoch,
                "Starting database compaction"
            );
            db.compact()?;

            let finish_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(start_time);
            db.store_compaction_timestamp(finish_time)?;

            info!("Database compaction complete");
        }
        Ok(())
    }
}
