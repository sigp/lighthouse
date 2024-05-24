use crate::beacon_chain::BEACON_CHAIN_DB_KEY;
use crate::errors::BeaconChainError;
use crate::head_tracker::{HeadTracker, SszHeadTracker};
use crate::persisted_beacon_chain::{PersistedBeaconChain, DUMMY_CANONICAL_HEAD_BLOCK_ROOT};
use parking_lot::Mutex;
use slog::{debug, error, info, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use store::hot_cold_store::{migrate_database, HotColdDBError};
use store::iter::RootsIterator;
use store::{Error, ItemStore, StoreItem, StoreOp};
pub use store::{HotColdDB, MemoryStore};
use types::{
    BeaconState, BeaconStateError, BeaconStateHash, Checkpoint, Epoch, EthSpec, Hash256,
    SignedBeaconBlockHash, Slot,
};

/// Compact at least this frequently, finalization permitting (7 days).
const MAX_COMPACTION_PERIOD_SECONDS: u64 = 604800;
/// Compact at *most* this frequently, to prevent over-compaction during sync (2 hours).
const MIN_COMPACTION_PERIOD_SECONDS: u64 = 7200;
/// Compact after a large finality gap, if we respect `MIN_COMPACTION_PERIOD_SECONDS`.
const COMPACTION_FINALITY_DISTANCE: u64 = 1024;

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
    /// Genesis block root, for persisting the `PersistedBeaconChain`.
    genesis_block_root: Hash256,
    log: Logger,
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
        old_finalized_checkpoint: Checkpoint,
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
}

/// Message sent to the migration thread containing the information it needs to run.
pub enum Notification {
    Finalization(FinalizationNotification),
    Reconstruction,
    PruneBlobs(Epoch),
}

pub struct FinalizationNotification {
    finalized_state_root: BeaconStateHash,
    finalized_checkpoint: Checkpoint,
    head_tracker: Arc<HeadTracker>,
    prev_migration: Arc<Mutex<PrevMigration>>,
    genesis_block_root: Hash256,
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> BackgroundMigrator<E, Hot, Cold> {
    /// Create a new `BackgroundMigrator` and spawn its thread if necessary.
    pub fn new(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        config: MigratorConfig,
        genesis_block_root: Hash256,
        log: Logger,
    ) -> Self {
        // Estimate last migration run from DB split slot.
        let prev_migration = Arc::new(Mutex::new(PrevMigration {
            epoch: db.get_split_slot().epoch(E::slots_per_epoch()),
            epochs_per_migration: config.epochs_per_migration,
        }));
        let tx_thread = if config.blocking {
            None
        } else {
            Some(Mutex::new(Self::spawn_thread(db.clone(), log.clone())))
        };
        Self {
            db,
            tx_thread,
            prev_migration,
            genesis_block_root,
            log,
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
        head_tracker: Arc<HeadTracker>,
    ) -> Result<(), BeaconChainError> {
        let notif = FinalizationNotification {
            finalized_state_root,
            finalized_checkpoint,
            head_tracker,
            prev_migration: self.prev_migration.clone(),
            genesis_block_root: self.genesis_block_root,
        };

        // Send to background thread if configured, otherwise run in foreground.
        if let Some(Notification::Finalization(notif)) =
            self.send_background_notification(Notification::Finalization(notif))
        {
            Self::run_migration(self.db.clone(), notif, &self.log);
        }

        Ok(())
    }

    pub fn process_reconstruction(&self) {
        if let Some(Notification::Reconstruction) =
            self.send_background_notification(Notification::Reconstruction)
        {
            Self::run_reconstruction(self.db.clone(), &self.log);
        }
    }

    pub fn process_prune_blobs(&self, data_availability_boundary: Epoch) {
        if let Some(Notification::PruneBlobs(data_availability_boundary)) =
            self.send_background_notification(Notification::PruneBlobs(data_availability_boundary))
        {
            Self::run_prune_blobs(self.db.clone(), data_availability_boundary, &self.log);
        }
    }

    pub fn run_reconstruction(db: Arc<HotColdDB<E, Hot, Cold>>, log: &Logger) {
        if let Err(e) = db.reconstruct_historic_states() {
            error!(
                log,
                "State reconstruction failed";
                "error" => ?e,
            );
        }
    }

    pub fn run_prune_blobs(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        data_availability_boundary: Epoch,
        log: &Logger,
    ) {
        if let Err(e) = db.try_prune_blobs(false, data_availability_boundary) {
            error!(
                log,
                "Blob pruning failed";
                "error" => ?e,
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
                let (new_tx, new_thread) = Self::spawn_thread(self.db.clone(), self.log.clone());

                *tx = new_tx;
                let old_thread = mem::replace(thread, new_thread);

                // Join the old thread, which will probably have panicked, or may have
                // halted normally just now as a result of us dropping the old `mpsc::Sender`.
                if let Err(thread_err) = old_thread.join() {
                    warn!(
                        self.log,
                        "Migration thread died, so it was restarted";
                        "reason" => format!("{:?}", thread_err)
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

    /// Perform the actual work of `process_finalization`.
    fn run_migration(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        notif: FinalizationNotification,
        log: &Logger,
    ) {
        // Do not run too frequently.
        let epoch = notif.finalized_checkpoint.epoch;
        let mut prev_migration = notif.prev_migration.lock();
        if epoch < prev_migration.epoch + prev_migration.epochs_per_migration {
            debug!(
                log,
                "Database consolidation deferred";
                "last_finalized_epoch" => prev_migration.epoch,
                "new_finalized_epoch" => epoch,
                "epochs_per_migration" => prev_migration.epochs_per_migration,
            );
            return;
        }

        // Update the previous migration epoch immediately to avoid holding the lock. If the
        // migration doesn't succeed then the next migration will be retried at the next scheduled
        // run.
        prev_migration.epoch = epoch;
        drop(prev_migration);

        debug!(log, "Database consolidation started");

        let finalized_state_root = notif.finalized_state_root;
        let finalized_block_root = notif.finalized_checkpoint.root;

        let finalized_state = match db.get_state(&finalized_state_root.into(), None) {
            Ok(Some(state)) => state,
            other => {
                error!(
                    log,
                    "Migrator failed to load state";
                    "state_root" => ?finalized_state_root,
                    "error" => ?other
                );
                return;
            }
        };

        let old_finalized_checkpoint = match Self::prune_abandoned_forks(
            db.clone(),
            notif.head_tracker,
            finalized_state_root,
            &finalized_state,
            notif.finalized_checkpoint,
            notif.genesis_block_root,
            log,
        ) {
            Ok(PruningOutcome::Successful {
                old_finalized_checkpoint,
            }) => old_finalized_checkpoint,
            Ok(PruningOutcome::DeferredConcurrentHeadTrackerMutation) => {
                warn!(
                    log,
                    "Pruning deferred because of a concurrent mutation";
                    "message" => "this is expected only very rarely!"
                );
                return;
            }
            Ok(PruningOutcome::OutOfOrderFinalization {
                old_finalized_checkpoint,
                new_finalized_checkpoint,
            }) => {
                warn!(
                    log,
                    "Ignoring out of order finalization request";
                    "old_finalized_epoch" => old_finalized_checkpoint.epoch,
                    "new_finalized_epoch" => new_finalized_checkpoint.epoch,
                    "message" => "this is expected occasionally due to a (harmless) race condition"
                );
                return;
            }
            Err(e) => {
                warn!(log, "Block pruning failed"; "error" => ?e);
                return;
            }
        };

        match migrate_database(
            db.clone(),
            finalized_state_root.into(),
            finalized_block_root,
            &finalized_state,
        ) {
            Ok(()) => {}
            Err(Error::HotColdDBError(HotColdDBError::FreezeSlotUnaligned(slot))) => {
                debug!(
                    log,
                    "Database migration postponed, unaligned finalized block";
                    "slot" => slot.as_u64()
                );
            }
            Err(e) => {
                warn!(
                    log,
                    "Database migration failed";
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        // Finally, compact the database so that new free space is properly reclaimed.
        if let Err(e) = Self::run_compaction(
            db,
            old_finalized_checkpoint.epoch,
            notif.finalized_checkpoint.epoch,
            log,
        ) {
            warn!(log, "Database compaction failed"; "error" => format!("{:?}", e));
        }

        debug!(log, "Database consolidation complete");
    }

    /// Spawn a new child thread to run the migration process.
    ///
    /// Return a channel handle for sending requests to the thread.
    fn spawn_thread(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        log: Logger,
    ) -> (mpsc::Sender<Notification>, thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok(notif) = rx.recv() {
                let mut reconstruction_notif = None;
                let mut finalization_notif = None;
                let mut prune_blobs_notif = None;
                match notif {
                    Notification::Reconstruction => reconstruction_notif = Some(notif),
                    Notification::Finalization(fin) => finalization_notif = Some(fin),
                    Notification::PruneBlobs(dab) => prune_blobs_notif = Some(dab),
                }
                // Read the rest of the messages in the channel, taking the best of each type.
                for notif in rx.try_iter() {
                    match notif {
                        Notification::Reconstruction => reconstruction_notif = Some(notif),
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
                // If reconstruction is on-going, ignore finalization migration and blob pruning.
                if reconstruction_notif.is_some() {
                    Self::run_reconstruction(db.clone(), &log);
                } else {
                    if let Some(fin) = finalization_notif {
                        Self::run_migration(db.clone(), fin, &log);
                    }
                    if let Some(dab) = prune_blobs_notif {
                        Self::run_prune_blobs(db.clone(), dab, &log);
                    }
                }
            }
        });
        (tx, thread)
    }

    /// Traverses live heads and prunes blocks and states of chains that we know can't be built
    /// upon because finalization would prohibit it. This is an optimisation intended to save disk
    /// space.
    #[allow(clippy::too_many_arguments)]
    fn prune_abandoned_forks(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        head_tracker: Arc<HeadTracker>,
        new_finalized_state_hash: BeaconStateHash,
        new_finalized_state: &BeaconState<E>,
        new_finalized_checkpoint: Checkpoint,
        genesis_block_root: Hash256,
        log: &Logger,
    ) -> Result<PruningOutcome, BeaconChainError> {
        let old_finalized_checkpoint =
            store
                .load_pruning_checkpoint()?
                .unwrap_or_else(|| Checkpoint {
                    epoch: Epoch::new(0),
                    root: Hash256::zero(),
                });

        let old_finalized_slot = old_finalized_checkpoint
            .epoch
            .start_slot(E::slots_per_epoch());
        let new_finalized_slot = new_finalized_checkpoint
            .epoch
            .start_slot(E::slots_per_epoch());
        let new_finalized_block_hash = new_finalized_checkpoint.root.into();

        // The finalized state must be for the epoch boundary slot, not the slot of the finalized
        // block.
        if new_finalized_state.slot() != new_finalized_slot {
            return Err(PruningError::IncorrectFinalizedState {
                state_slot: new_finalized_state.slot(),
                new_finalized_slot,
            }
            .into());
        }

        // The new finalized state must be newer than the previous finalized state.
        // I think this can happen sometimes currently due to `fork_choice` running in parallel
        // with itself and sending us notifications out of order.
        if old_finalized_slot > new_finalized_slot {
            return Ok(PruningOutcome::OutOfOrderFinalization {
                old_finalized_checkpoint,
                new_finalized_checkpoint,
            });
        }

        debug!(
            log,
            "Starting database pruning";
            "old_finalized_epoch" => old_finalized_checkpoint.epoch,
            "new_finalized_epoch" => new_finalized_checkpoint.epoch,
        );
        // For each slot between the new finalized checkpoint and the old finalized checkpoint,
        // collect the beacon block root and state root of the canonical chain.
        let newly_finalized_chain: HashMap<Slot, (SignedBeaconBlockHash, BeaconStateHash)> =
            std::iter::once(Ok((
                new_finalized_slot,
                (new_finalized_block_hash, new_finalized_state_hash),
            )))
            .chain(RootsIterator::new(&store, new_finalized_state).map(|res| {
                res.map(|(block_root, state_root, slot)| {
                    (slot, (block_root.into(), state_root.into()))
                })
            }))
            .take_while(|res| {
                res.as_ref()
                    .map_or(true, |(slot, _)| *slot >= old_finalized_slot)
            })
            .collect::<Result<_, _>>()?;

        // We don't know which blocks are shared among abandoned chains, so we buffer and delete
        // everything in one fell swoop.
        let mut abandoned_blocks: HashSet<SignedBeaconBlockHash> = HashSet::new();
        let mut abandoned_states: HashSet<(Slot, BeaconStateHash)> = HashSet::new();
        let mut abandoned_heads: HashSet<Hash256> = HashSet::new();

        let heads = head_tracker.heads();
        debug!(
            log,
            "Extra pruning information";
            "old_finalized_root" => format!("{:?}", old_finalized_checkpoint.root),
            "new_finalized_root" => format!("{:?}", new_finalized_checkpoint.root),
            "head_count" => heads.len(),
        );

        for (head_hash, head_slot) in heads {
            // Load head block. If it fails with a decode error, it's likely a reverted block,
            // so delete it from the head tracker but leave it and its states in the database
            // This is suboptimal as it wastes disk space, but it's difficult to fix. A re-sync
            // can be used to reclaim the space.
            let head_state_root = match store.get_blinded_block(&head_hash) {
                Ok(Some(block)) => block.state_root(),
                Ok(None) => {
                    return Err(BeaconStateError::MissingBeaconBlock(head_hash.into()).into())
                }
                Err(Error::SszDecodeError(e)) => {
                    warn!(
                        log,
                        "Forgetting invalid head block";
                        "block_root" => ?head_hash,
                        "error" => ?e,
                    );
                    abandoned_heads.insert(head_hash);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            let mut potentially_abandoned_head = Some(head_hash);
            let mut potentially_abandoned_blocks = vec![];

            // Iterate backwards from this head, staging blocks and states for deletion.
            let iter = std::iter::once(Ok((head_hash, head_state_root, head_slot)))
                .chain(RootsIterator::from_block(&store, head_hash)?);

            for maybe_tuple in iter {
                let (block_root, state_root, slot) = maybe_tuple?;
                let block_root = SignedBeaconBlockHash::from(block_root);
                let state_root = BeaconStateHash::from(state_root);

                match newly_finalized_chain.get(&slot) {
                    // If there's no information about a slot on the finalized chain, then
                    // it should be because it's ahead of the new finalized slot. Stage
                    // the fork's block and state for possible deletion.
                    None => {
                        if slot > new_finalized_slot {
                            potentially_abandoned_blocks.push((
                                slot,
                                Some(block_root),
                                Some(state_root),
                            ));
                        } else if slot >= old_finalized_slot {
                            return Err(PruningError::MissingInfoForCanonicalChain { slot }.into());
                        } else {
                            // We must assume here any candidate chains include the old finalized
                            // checkpoint, i.e. there aren't any forks starting at a block that is a
                            // strict ancestor of old_finalized_checkpoint.
                            warn!(
                                log,
                                "Found a chain that should already have been pruned";
                                "head_block_root" => format!("{:?}", head_hash),
                                "head_slot" => head_slot,
                            );
                            potentially_abandoned_head.take();
                            break;
                        }
                    }
                    Some((finalized_block_root, finalized_state_root)) => {
                        // This fork descends from a newly finalized block, we can stop.
                        if block_root == *finalized_block_root {
                            // Sanity check: if the slot and block root match, then the
                            // state roots should match too.
                            if state_root != *finalized_state_root {
                                return Err(PruningError::UnexpectedUnequalStateRoots.into());
                            }

                            // If the fork descends from the whole finalized chain,
                            // do not prune it. Otherwise continue to delete all
                            // of the blocks and states that have been staged for
                            // deletion so far.
                            if slot == new_finalized_slot {
                                potentially_abandoned_blocks.clear();
                                potentially_abandoned_head.take();
                            }
                            // If there are skipped slots on the fork to be pruned, then
                            // we will have just staged the common block for deletion.
                            // Unstage it.
                            else {
                                for (_, block_root, _) in
                                    potentially_abandoned_blocks.iter_mut().rev()
                                {
                                    if block_root.as_ref() == Some(finalized_block_root) {
                                        *block_root = None;
                                    } else {
                                        break;
                                    }
                                }
                            }
                            break;
                        } else {
                            if state_root == *finalized_state_root {
                                return Err(PruningError::UnexpectedEqualStateRoots.into());
                            }
                            potentially_abandoned_blocks.push((
                                slot,
                                Some(block_root),
                                Some(state_root),
                            ));
                        }
                    }
                }
            }

            if let Some(abandoned_head) = potentially_abandoned_head {
                debug!(
                    log,
                    "Pruning head";
                    "head_block_root" => format!("{:?}", abandoned_head),
                    "head_slot" => head_slot,
                );
                abandoned_heads.insert(abandoned_head);
                abandoned_blocks.extend(
                    potentially_abandoned_blocks
                        .iter()
                        .filter_map(|(_, maybe_block_hash, _)| *maybe_block_hash),
                );
                abandoned_states.extend(potentially_abandoned_blocks.iter().filter_map(
                    |(slot, _, maybe_state_hash)| maybe_state_hash.map(|sr| (*slot, sr)),
                ));
            }
        }

        // Update the head tracker before the database, so that we maintain the invariant
        // that a block present in the head tracker is present in the database.
        // See https://github.com/sigp/lighthouse/issues/1557
        let mut head_tracker_lock = head_tracker.0.write();

        // Check that all the heads to be deleted are still present. The absence of any
        // head indicates a race, that will likely resolve itself, so we defer pruning until
        // later.
        for head_hash in &abandoned_heads {
            if !head_tracker_lock.contains_key(head_hash) {
                return Ok(PruningOutcome::DeferredConcurrentHeadTrackerMutation);
            }
        }

        // Then remove them for real.
        for head_hash in abandoned_heads {
            head_tracker_lock.remove(&head_hash);
        }

        let mut batch: Vec<StoreOp<E>> = abandoned_blocks
            .into_iter()
            .map(Into::into)
            .flat_map(|block_root: Hash256| {
                [
                    StoreOp::DeleteBlock(block_root),
                    StoreOp::DeleteExecutionPayload(block_root),
                    StoreOp::DeleteBlobs(block_root),
                ]
            })
            .chain(
                abandoned_states
                    .into_iter()
                    .map(|(slot, state_hash)| StoreOp::DeleteState(state_hash.into(), Some(slot))),
            )
            .collect();

        // Persist the head in case the process is killed or crashes here. This prevents
        // the head tracker reverting after our mutation above.
        let persisted_head = PersistedBeaconChain {
            _canonical_head_block_root: DUMMY_CANONICAL_HEAD_BLOCK_ROOT,
            genesis_block_root,
            ssz_head_tracker: SszHeadTracker::from_map(&head_tracker_lock),
        };
        drop(head_tracker_lock);
        batch.push(StoreOp::KeyValueOp(
            persisted_head.as_kv_store_op(BEACON_CHAIN_DB_KEY),
        ));

        // Persist the new finalized checkpoint as the pruning checkpoint.
        batch.push(StoreOp::KeyValueOp(
            store.pruning_checkpoint_store_op(new_finalized_checkpoint),
        ));

        store.do_atomically_with_block_and_blobs_cache(batch)?;

        // Do a quick separate pass to delete obsoleted hot states, usually pre-states from the state
        // advance which are not canonical due to blocks being applied on top.
        store.prune_old_hot_states()?;

        debug!(log, "Database pruning complete");

        Ok(PruningOutcome::Successful {
            old_finalized_checkpoint,
        })
    }

    /// Compact the database if it has been more than `COMPACTION_PERIOD_SECONDS` since it
    /// was last compacted.
    pub fn run_compaction(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        old_finalized_epoch: Epoch,
        new_finalized_epoch: Epoch,
        log: &Logger,
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
                log,
                "Starting database compaction";
                "old_finalized_epoch" => old_finalized_epoch,
                "new_finalized_epoch" => new_finalized_epoch,
            );
            db.compact()?;

            let finish_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(start_time);
            db.store_compaction_timestamp(finish_time)?;

            info!(log, "Database compaction complete");
        }
        Ok(())
    }
}
