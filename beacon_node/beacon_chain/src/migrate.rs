use crate::errors::BeaconChainError;
use crate::head_tracker::HeadTracker;
use parking_lot::Mutex;
use slog::{debug, error, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use store::hot_cold_store::{process_finalization, HotColdDBError};
use store::iter::RootsIterator;
use store::{Error, ItemStore, StoreOp};
pub use store::{HotColdDB, MemoryStore};
use types::{
    BeaconState, BeaconStateError, BeaconStateHash, Checkpoint, EthSpec, Hash256,
    SignedBeaconBlockHash, Slot,
};

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

/// Trait for migration processes that update the database upon finalization.
pub trait Migrate<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>:
    Send + Sync + 'static
{
    fn new(db: Arc<HotColdDB<E, Hot, Cold>>, log: Logger) -> Self;

    fn process_finalization(
        &self,
        _finalized_state_root: BeaconStateHash,
        _new_finalized_state: BeaconState<E>,
        _head_tracker: Arc<HeadTracker>,
        _old_finalized_checkpoint: Checkpoint,
        _new_finalized_checkpoint: Checkpoint,
    ) {
    }

    /// Traverses live heads and prunes blocks and states of chains that we know can't be built
    /// upon because finalization would prohibit it. This is an optimisation intended to save disk
    /// space.
    ///
    /// Assumptions:
    ///  * It is called after every finalization.
    fn prune_abandoned_forks(
        store: Arc<HotColdDB<E, Hot, Cold>>,
        head_tracker: Arc<HeadTracker>,
        new_finalized_state_hash: BeaconStateHash,
        new_finalized_state: &BeaconState<E>,
        old_finalized_checkpoint: Checkpoint,
        new_finalized_checkpoint: Checkpoint,
        log: &Logger,
    ) -> Result<(), BeaconChainError> {
        // There will never be any blocks to prune if there is only a single head in the chain.
        if head_tracker.heads().len() == 1 {
            return Ok(());
        }

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

        debug!(
            log,
            "Starting database pruning";
            "old_finalized_epoch" => old_finalized_checkpoint.epoch,
            "old_finalized_root" => format!("{:?}", old_finalized_checkpoint.root),
            "new_finalized_epoch" => new_finalized_checkpoint.epoch,
            "new_finalized_root" => format!("{:?}", new_finalized_checkpoint.root),
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

        for (head_hash, head_slot) in head_tracker.heads() {
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

        let batch: Vec<StoreOp<E>> = abandoned_blocks
            .into_iter()
            .map(StoreOp::DeleteBlock)
            .chain(
                abandoned_states
                    .into_iter()
                    .map(|(slot, state_hash)| StoreOp::DeleteState(state_hash, slot)),
            )
            .collect();
        store.do_atomically(batch)?;
        for head_hash in abandoned_heads.into_iter() {
            head_tracker.remove_head(head_hash);
        }

        debug!(log, "Database pruning complete");

        Ok(())
    }
}

/// Migrator that does nothing, for stores that don't need migration.
pub struct NullMigrator;

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Migrate<E, Hot, Cold> for NullMigrator {
    fn new(_: Arc<HotColdDB<E, Hot, Cold>>, _: Logger) -> Self {
        NullMigrator
    }
}

/// Migrator that immediately calls the store's migration function, blocking the current execution.
///
/// Mostly useful for tests.
pub struct BlockingMigrator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    db: Arc<HotColdDB<E, Hot, Cold>>,
    log: Logger,
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Migrate<E, Hot, Cold>
    for BlockingMigrator<E, Hot, Cold>
{
    fn new(db: Arc<HotColdDB<E, Hot, Cold>>, log: Logger) -> Self {
        BlockingMigrator { db, log }
    }

    fn process_finalization(
        &self,
        finalized_state_root: BeaconStateHash,
        new_finalized_state: BeaconState<E>,
        head_tracker: Arc<HeadTracker>,
        old_finalized_checkpoint: Checkpoint,
        new_finalized_checkpoint: Checkpoint,
    ) {
        if let Err(e) = Self::prune_abandoned_forks(
            self.db.clone(),
            head_tracker,
            finalized_state_root,
            &new_finalized_state,
            old_finalized_checkpoint,
            new_finalized_checkpoint,
            &self.log,
        ) {
            error!(&self.log, "Pruning error"; "error" => format!("{:?}", e));
        }

        if let Err(e) = process_finalization(
            self.db.clone(),
            finalized_state_root.into(),
            &new_finalized_state,
        ) {
            error!(&self.log, "Migration error"; "error" => format!("{:?}", e));
        }
    }
}

type MpscSender<E> = mpsc::Sender<(
    BeaconStateHash,
    BeaconState<E>,
    Arc<HeadTracker>,
    Checkpoint,
    Checkpoint,
)>;

/// Migrator that runs a background thread to migrate state from the hot to the cold database.
pub struct BackgroundMigrator<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    db: Arc<HotColdDB<E, Hot, Cold>>,
    tx_thread: Mutex<(MpscSender<E>, thread::JoinHandle<()>)>,
    log: Logger,
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Migrate<E, Hot, Cold>
    for BackgroundMigrator<E, Hot, Cold>
{
    fn new(db: Arc<HotColdDB<E, Hot, Cold>>, log: Logger) -> Self {
        let tx_thread = Mutex::new(Self::spawn_thread(db.clone(), log.clone()));
        Self { db, tx_thread, log }
    }

    fn process_finalization(
        &self,
        finalized_state_root: BeaconStateHash,
        new_finalized_state: BeaconState<E>,
        head_tracker: Arc<HeadTracker>,
        old_finalized_checkpoint: Checkpoint,
        new_finalized_checkpoint: Checkpoint,
    ) {
        let (ref mut tx, ref mut thread) = *self.tx_thread.lock();

        if let Err(tx_err) = tx.send((
            finalized_state_root,
            new_finalized_state,
            head_tracker,
            old_finalized_checkpoint,
            new_finalized_checkpoint,
        )) {
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
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> BackgroundMigrator<E, Hot, Cold> {
    /// Spawn a new child thread to run the migration process.
    ///
    /// Return a channel handle for sending new finalized states to the thread.
    fn spawn_thread(
        db: Arc<HotColdDB<E, Hot, Cold>>,
        log: Logger,
    ) -> (MpscSender<E>, thread::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok((
                state_root,
                state,
                head_tracker,
                old_finalized_checkpoint,
                new_finalized_checkpoint,
            )) = rx.recv()
            {
                match Self::prune_abandoned_forks(
                    db.clone(),
                    head_tracker,
                    state_root,
                    &state,
                    old_finalized_checkpoint,
                    new_finalized_checkpoint,
                    &log,
                ) {
                    Ok(()) => {}
                    Err(e) => warn!(log, "Block pruning failed: {:?}", e),
                }

                match process_finalization(db.clone(), state_root.into(), &state) {
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
                    }
                };
            }
        });

        (tx, thread)
    }
}
