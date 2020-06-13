use crate::errors::BeaconChainError;
use crate::head_tracker::HeadTracker;
use parking_lot::Mutex;
use slog::{debug, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use store::hot_cold_store::{process_finalization, HotColdDBError};
use store::iter::{ParentRootBlockIterator, RootsIterator};
use store::{Error, Store, StoreOp};
pub use store::{HotColdDB, MemoryStore};
use types::*;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// Trait for migration processes that update the database upon finalization.
pub trait Migrate<E: EthSpec>: Send + Sync + 'static {
    fn new(db: Arc<HotColdDB<E>>, log: Logger) -> Self;

    fn process_finalization(
        &self,
        _state_root: Hash256,
        _new_finalized_state: BeaconState<E>,
        _max_finality_distance: u64,
        _head_tracker: Arc<HeadTracker>,
        _old_finalized_block_hash: SignedBeaconBlockHash,
        _new_finalized_block_hash: SignedBeaconBlockHash,
    ) {
    }

    /// Traverses live heads and prunes blocks and states of chains that we know can't be built
    /// upon because finalization would prohibit it.  This is a optimisation intended to save disk
    /// space.
    ///
    /// Assumptions:
    ///  * It is called after every finalization.
    fn prune_abandoned_forks(
        store: Arc<HotColdDB<E>>,
        head_tracker: Arc<HeadTracker>,
        old_finalized_block_hash: SignedBeaconBlockHash,
        new_finalized_block_hash: SignedBeaconBlockHash,
        new_finalized_slot: Slot,
    ) -> Result<(), BeaconChainError> {
        // There will never be any blocks to prune if there is only a single head in the chain.
        if head_tracker.heads().len() == 1 {
            return Ok(());
        }

        let old_finalized_slot = store
            .get_block(&old_finalized_block_hash.into())?
            .ok_or_else(|| BeaconChainError::MissingBeaconBlock(old_finalized_block_hash.into()))?
            .slot();

        // Collect hashes from new_finalized_block back to old_finalized_block (inclusive)
        let mut found_block = false; // hack for `take_until`
        let newly_finalized_blocks: HashMap<SignedBeaconBlockHash, Slot> =
            ParentRootBlockIterator::new(&*store, new_finalized_block_hash.into())
                .take_while(|result| match result {
                    Ok((block_hash, _)) => {
                        if found_block {
                            false
                        } else {
                            found_block |= *block_hash == old_finalized_block_hash.into();
                            true
                        }
                    }
                    Err(_) => true,
                })
                .map(|result| result.map(|(block_hash, block)| (block_hash.into(), block.slot())))
                .collect::<Result<_, _>>()?;

        // We don't know which blocks are shared among abandoned chains, so we buffer and delete
        // everything in one fell swoop.
        let mut abandoned_blocks: HashSet<SignedBeaconBlockHash> = HashSet::new();
        let mut abandoned_states: HashSet<(Slot, BeaconStateHash)> = HashSet::new();
        let mut abandoned_heads: HashSet<Hash256> = HashSet::new();

        for (head_hash, head_slot) in head_tracker.heads() {
            let mut potentially_abandoned_head: Option<Hash256> = Some(head_hash);
            let mut potentially_abandoned_blocks: Vec<(
                Slot,
                Option<SignedBeaconBlockHash>,
                Option<BeaconStateHash>,
            )> = Vec::new();

            let head_state_hash = store
                .get_block(&head_hash)?
                .ok_or_else(|| BeaconStateError::MissingBeaconBlock(head_hash.into()))?
                .state_root();

            let iter = std::iter::once(Ok((head_hash, head_state_hash, head_slot)))
                .chain(RootsIterator::from_block(Arc::clone(&store), head_hash)?);
            for maybe_tuple in iter {
                let (block_hash, state_hash, slot) = maybe_tuple?;
                if slot < old_finalized_slot {
                    // We must assume here any candidate chains include old_finalized_block_hash,
                    // i.e. there aren't any forks starting at a block that is a strict ancestor of
                    // old_finalized_block_hash.
                    break;
                }
                match newly_finalized_blocks.get(&block_hash.into()).copied() {
                    // Block is not finalized, mark it and its state for deletion
                    None => {
                        potentially_abandoned_blocks.push((
                            slot,
                            Some(block_hash.into()),
                            Some(state_hash.into()),
                        ));
                    }
                    Some(finalized_slot) => {
                        // Block root is finalized, and we have reached the slot it was finalized
                        // at: we've hit a shared part of the chain.
                        if finalized_slot == slot {
                            // The first finalized block of a candidate chain lies after (in terms
                            // of slots order) the newly finalized block.  It's not a candidate for
                            // prunning.
                            if finalized_slot == new_finalized_slot {
                                potentially_abandoned_blocks.clear();
                                potentially_abandoned_head.take();
                            }

                            break;
                        }
                        // Block root is finalized, but we're at a skip slot: delete the state only.
                        else {
                            potentially_abandoned_blocks.push((
                                slot,
                                None,
                                Some(state_hash.into()),
                            ));
                        }
                    }
                }
            }

            abandoned_heads.extend(potentially_abandoned_head.into_iter());
            if !potentially_abandoned_blocks.is_empty() {
                abandoned_blocks.extend(
                    potentially_abandoned_blocks
                        .iter()
                        .filter_map(|(_, maybe_block_hash, _)| *maybe_block_hash),
                );
                abandoned_states.extend(potentially_abandoned_blocks.iter().filter_map(
                    |(slot, _, maybe_state_hash)| match maybe_state_hash {
                        None => None,
                        Some(state_hash) => Some((*slot, *state_hash)),
                    },
                ));
            }
        }

        let batch: Vec<StoreOp> = abandoned_blocks
            .into_iter()
            .map(|block_hash| StoreOp::DeleteBlock(block_hash))
            .chain(
                abandoned_states
                    .into_iter()
                    .map(|(slot, state_hash)| StoreOp::DeleteState(state_hash, slot)),
            )
            .collect();
        store.do_atomically(&batch)?;
        for head_hash in abandoned_heads.into_iter() {
            head_tracker.remove_head(head_hash);
        }

        Ok(())
    }
}

/// Migrator that does nothing, for stores that don't need migration.
pub struct NullMigrator;

impl<E: EthSpec> Migrate<E> for NullMigrator {
    fn new(_: Arc<HotColdDB<E>>, _: Logger) -> Self {
        NullMigrator
    }
}

/// Migrator that immediately calls the store's migration function, blocking the current execution.
///
/// Mostly useful for tests.
pub struct BlockingMigrator<E: EthSpec> {
    db: Arc<HotColdDB<E>>,
}

impl<E: EthSpec> Migrate<E> for BlockingMigrator<E> {
    fn new(db: Arc<HotColdDB<E>>, _: Logger) -> Self {
        BlockingMigrator { db }
    }

    fn process_finalization(
        &self,
        state_root: Hash256,
        new_finalized_state: BeaconState<E>,
        _max_finality_distance: u64,
        head_tracker: Arc<HeadTracker>,
        old_finalized_block_hash: SignedBeaconBlockHash,
        new_finalized_block_hash: SignedBeaconBlockHash,
    ) {
        if let Err(e) = process_finalization(self.db.clone(), state_root, &new_finalized_state) {
            // This migrator is only used for testing, so we just log to stderr without a logger.
            eprintln!("Migration error: {:?}", e);
        }

        if let Err(e) = Self::prune_abandoned_forks(
            self.db.clone(),
            head_tracker,
            old_finalized_block_hash,
            new_finalized_block_hash,
            new_finalized_state.slot,
        ) {
            eprintln!("Pruning error: {:?}", e);
        }
    }
}

type MpscSender<E> = mpsc::Sender<(
    Hash256,
    BeaconState<E>,
    Arc<HeadTracker>,
    SignedBeaconBlockHash,
    SignedBeaconBlockHash,
    Slot,
)>;

/// Migrator that runs a background thread to migrate state from the hot to the cold database.
pub struct BackgroundMigrator<E: EthSpec> {
    db: Arc<HotColdDB<E>>,
    tx_thread: Mutex<(MpscSender<E>, thread::JoinHandle<()>)>,
    log: Logger,
}

impl<E: EthSpec> Migrate<E> for BackgroundMigrator<E> {
    fn new(db: Arc<HotColdDB<E>>, log: Logger) -> Self {
        let tx_thread = Mutex::new(Self::spawn_thread(db.clone(), log.clone()));
        Self { db, tx_thread, log }
    }

    /// Perform the freezing operation on the database,
    fn process_finalization(
        &self,
        finalized_state_root: Hash256,
        new_finalized_state: BeaconState<E>,
        max_finality_distance: u64,
        head_tracker: Arc<HeadTracker>,
        old_finalized_block_hash: SignedBeaconBlockHash,
        new_finalized_block_hash: SignedBeaconBlockHash,
    ) {
        if !self.needs_migration(new_finalized_state.slot, max_finality_distance) {
            return;
        }

        let (ref mut tx, ref mut thread) = *self.tx_thread.lock();

        let new_finalized_slot = new_finalized_state.slot;
        if let Err(tx_err) = tx.send((
            finalized_state_root,
            new_finalized_state,
            head_tracker,
            old_finalized_block_hash,
            new_finalized_block_hash,
            new_finalized_slot,
        )) {
            let (new_tx, new_thread) = Self::spawn_thread(self.db.clone(), self.log.clone());

            drop(mem::replace(tx, new_tx));
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

impl<E: EthSpec> BackgroundMigrator<E> {
    /// Return true if a migration needs to be performed, given a new `finalized_slot`.
    fn needs_migration(&self, finalized_slot: Slot, max_finality_distance: u64) -> bool {
        let finality_distance = finalized_slot - self.db.get_split_slot();
        finality_distance > max_finality_distance
    }

    /// Spawn a new child thread to run the migration process.
    ///
    /// Return a channel handle for sending new finalized states to the thread.
    fn spawn_thread(
        db: Arc<HotColdDB<E>>,
        log: Logger,
    ) -> (
        mpsc::Sender<(
            Hash256,
            BeaconState<E>,
            Arc<HeadTracker>,
            SignedBeaconBlockHash,
            SignedBeaconBlockHash,
            Slot,
        )>,
        thread::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok((
                state_root,
                state,
                head_tracker,
                old_finalized_block_hash,
                new_finalized_block_hash,
                new_finalized_slot,
            )) = rx.recv()
            {
                match process_finalization(db.clone(), state_root, &state) {
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

                match Self::prune_abandoned_forks(
                    db.clone(),
                    head_tracker,
                    old_finalized_block_hash,
                    new_finalized_block_hash,
                    new_finalized_slot,
                ) {
                    Ok(()) => {}
                    Err(e) => warn!(log, "Block pruning failed: {:?}", e),
                }
            }
        });

        (tx, thread)
    }
}
