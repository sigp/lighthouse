use crate::{DiskStore, MemoryStore, SimpleDiskStore, Store};
use parking_lot::Mutex;
use slog::warn;
use std::mem;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use types::{BeaconState, EthSpec, Hash256, Slot};

/// Trait for migration processes that update the database upon finalization.
pub trait Migrate<S, E: EthSpec>: Send + Sync + 'static {
    fn new(db: Arc<S>) -> Self;

    fn freeze_to_state(
        &self,
        _state_root: Hash256,
        _state: BeaconState<E>,
        _max_finality_distance: u64,
    ) {
    }
}

/// Migrator that does nothing, for stores that don't need migration.
pub struct NullMigrator;

impl<E: EthSpec> Migrate<SimpleDiskStore, E> for NullMigrator {
    fn new(_: Arc<SimpleDiskStore>) -> Self {
        NullMigrator
    }
}

impl<E: EthSpec> Migrate<MemoryStore, E> for NullMigrator {
    fn new(_: Arc<MemoryStore>) -> Self {
        NullMigrator
    }
}

/// Migrator that immediately calls the store's migration function, blocking the current execution.
///
/// Mostly useful for tests.
pub struct BlockingMigrator<S>(Arc<S>);

impl<E: EthSpec, S: Store> Migrate<S, E> for BlockingMigrator<S> {
    fn new(db: Arc<S>) -> Self {
        BlockingMigrator(db)
    }

    fn freeze_to_state(
        &self,
        state_root: Hash256,
        state: BeaconState<E>,
        _max_finality_distance: u64,
    ) {
        if let Err(e) = S::freeze_to_state(self.0.clone(), state_root, &state) {
            // This migrator is only used for testing, so we just log to stderr without a logger.
            eprintln!("Migration error: {:?}", e);
        }
    }
}

/// Migrator that runs a background thread to migrate state from the hot to the cold database.
pub struct BackgroundMigrator<E: EthSpec> {
    db: Arc<DiskStore>,
    tx_thread: Mutex<(
        mpsc::Sender<(Hash256, BeaconState<E>)>,
        thread::JoinHandle<()>,
    )>,
}

impl<E: EthSpec> Migrate<DiskStore, E> for BackgroundMigrator<E> {
    fn new(db: Arc<DiskStore>) -> Self {
        let tx_thread = Mutex::new(Self::spawn_thread(db.clone()));
        Self { db, tx_thread }
    }

    /// Perform the freezing operation on the database,
    fn freeze_to_state(
        &self,
        finalized_state_root: Hash256,
        finalized_state: BeaconState<E>,
        max_finality_distance: u64,
    ) {
        if !self.needs_migration(finalized_state.slot, max_finality_distance) {
            return;
        }

        let (ref mut tx, ref mut thread) = *self.tx_thread.lock();

        if let Err(tx_err) = tx.send((finalized_state_root, finalized_state)) {
            let (new_tx, new_thread) = Self::spawn_thread(self.db.clone());

            drop(mem::replace(tx, new_tx));
            let old_thread = mem::replace(thread, new_thread);

            // Join the old thread, which will probably have panicked, or may have
            // halted normally just now as a result of us dropping the old `mpsc::Sender`.
            if let Err(thread_err) = old_thread.join() {
                warn!(
                    self.db.log,
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
        db: Arc<DiskStore>,
    ) -> (
        mpsc::Sender<(Hash256, BeaconState<E>)>,
        thread::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok((state_root, state)) = rx.recv() {
                if let Err(e) = DiskStore::freeze_to_state(db.clone(), state_root, &state) {
                    warn!(
                        db.log,
                        "Database migration failed";
                        "error" => format!("{:?}", e)
                    );
                }
            }
        });

        (tx, thread)
    }
}
