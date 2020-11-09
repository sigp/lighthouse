use crate::beacon_chain::BEACON_CHAIN_DB_KEY;
use crate::errors::BeaconChainError;
use crate::head_tracker::{HeadTracker, SszHeadTracker};
use crate::persisted_beacon_chain::{PersistedBeaconChain, DUMMY_CANONICAL_HEAD_BLOCK_ROOT};
use parking_lot::Mutex;
use slog::{debug, error, info, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use store::hot_cold_store::{migrate_database, HotColdDBError};
use store::iter::RootsIterator;
use store::{Error, ItemStore, StoreItem, StoreOp};
pub use store::{HotColdDB, MemoryStore};
use types::{
    BeaconState, BeaconStateError, BeaconStateHash, Checkpoint, Epoch, EthSpec, Hash256,
    SignedBeaconBlockHash, Slot,
};

/// The background migrator runs a thread to perform pruning and migrate state from the hot
/// to the cold database.
pub struct BackgroundMigrator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    db: Arc<HotColdDB<E, Hot, Cold>>,
    #[allow(clippy::type_complexity)]
    tx_thread: Option<
        Mutex<(
            mpsc::Sender<MigrationNotification<E>>,
            thread::JoinHandle<()>,
        )>,
    >,
    /// Genesis block root, for persisting the `PersistedBeaconChain`.
    genesis_block_root: Hash256,
    log: Logger,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigratorConfig {
    pub blocking: bool,
}

impl MigratorConfig {
    pub fn blocking(mut self) -> Self {
        self.blocking = true;
        self
    }
}

/// Pruning can be successful, or in rare cases deferred to a later point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruningOutcome {
    Successful,
    DeferredConcurrentMutation,
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
    UnexpectedEqualStateRoots,
    UnexpectedUnequalStateRoots,
}

/// Message sent to the migration thread containing the information it needs to run.
pub struct MigrationNotification<E: EthSpec> {
    finalized_state_root: BeaconStateHash,
    finalized_state: BeaconState<E>,
    finalized_checkpoint: Checkpoint,
    head_tracker: Arc<HeadTracker>,
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
        let tx_thread = if config.blocking {
            None
        } else {
            Some(Mutex::new(Self::spawn_thread(db.clone(), log.clone())))
        };
        Self {
            db,
            tx_thread,
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
        finalized_state: BeaconState<E>,
        finalized_checkpoint: Checkpoint,
        head_tracker: Arc<HeadTracker>,
    ) -> Result<(), BeaconChainError> {
        let notif = MigrationNotification {
            finalized_state_root,
            finalized_state,
            finalized_checkpoint,
            head_tracker,
            genesis_block_root: self.genesis_block_root,
        };

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
        }
        // Synchronous path, on the current thread.
        else {
            Self::run_migration(self.db.clone(), notif, &self.log)
        }

        Ok(())
    }

    /// Perform the actual work of `process_finalization`.
    fn run_migration(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        notif: MigrationNotification<E>,
        log: &Logger,
    ) {
        let finalized_state_root = notif.finalized_state_root;
        let finalized_state = notif.finalized_state;

        match Self::prune_abandoned_forks(
            db.clone(),
            notif.head_tracker,
            finalized_state_root,
            &finalized_state,
            notif.finalized_checkpoint,
            notif.genesis_block_root,
            log,
        ) {
            Ok(PruningOutcome::Successful) => {}
            Ok(PruningOutcome::DeferredConcurrentMutation) => {
                warn!(
                    log,
                    "Pruning deferred because of a concurrent mutation";
                    "message" => "this is expected only very rarely!"
                );
                return;
            }
            Err(e) => {
                warn!(log, "Block pruning failed"; "error" => format!("{:?}", e));
                return;
            }
        };

        match migrate_database(db.clone(), finalized_state_root.into(), &finalized_state) {
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
        debug!(log, "Starting database compaction");
        if let Err(e) = db.compact() {
            error!(
                log,
                "Database compaction failed";
                "error" => format!("{:?}", e)
            );
        }
        debug!(log, "Database compaction complete");
    }

    /// Spawn a new child thread to run the migration process.
    ///
    /// Return a channel handle for sending new finalized states to the thread.
    fn spawn_thread(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        log: Logger,
    ) -> (
        mpsc::Sender<MigrationNotification<E>>,
        thread::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok(notif) = rx.recv() {
                Self::run_migration(db.clone(), notif, &log);
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
        if new_finalized_state.slot != new_finalized_slot {
            return Err(PruningError::IncorrectFinalizedState {
                state_slot: new_finalized_state.slot,
                new_finalized_slot,
            }
            .into());
        }

        info!(
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
            .chain(
                RootsIterator::new(store.clone(), new_finalized_state).map(|res| {
                    res.map(|(block_root, state_root, slot)| {
                        (slot, (block_root.into(), state_root.into()))
                    })
                }),
            )
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
            let mut potentially_abandoned_head = Some(head_hash);
            let mut potentially_abandoned_blocks = vec![];

            let head_state_hash = store
                .get_block(&head_hash)?
                .ok_or_else(|| BeaconStateError::MissingBeaconBlock(head_hash.into()))?
                .state_root();

            // Iterate backwards from this head, staging blocks and states for deletion.
            let iter = std::iter::once(Ok((head_hash, head_state_hash, head_slot)))
                .chain(RootsIterator::from_block(store.clone(), head_hash)?);

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
                return Ok(PruningOutcome::DeferredConcurrentMutation);
            }
        }

        // Then remove them for real.
        for head_hash in abandoned_heads {
            head_tracker_lock.remove(&head_hash);
        }

        let batch: Vec<StoreOp<E>> = abandoned_blocks
            .into_iter()
            .map(Into::into)
            .map(StoreOp::DeleteBlock)
            .chain(
                abandoned_states
                    .into_iter()
                    .map(|(slot, state_hash)| StoreOp::DeleteState(state_hash.into(), Some(slot))),
            )
            .collect();

        let mut kv_batch = store.convert_to_kv_batch(&batch)?;

        // Persist the head in case the process is killed or crashes here. This prevents
        // the head tracker reverting after our mutation above.
        let persisted_head = PersistedBeaconChain {
            _canonical_head_block_root: DUMMY_CANONICAL_HEAD_BLOCK_ROOT,
            genesis_block_root,
            ssz_head_tracker: SszHeadTracker::from_map(&*head_tracker_lock),
        };
        drop(head_tracker_lock);
        kv_batch.push(persisted_head.as_kv_store_op(BEACON_CHAIN_DB_KEY));

        // Persist the new finalized checkpoint as the pruning checkpoint.
        kv_batch.push(store.pruning_checkpoint_store_op(new_finalized_checkpoint));

        store.hot_db.do_atomically(kv_batch)?;
        info!(log, "Database pruning complete");

        Ok(PruningOutcome::Successful)
    }
}
