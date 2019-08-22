use crate::{hot_cold_store::HotColdDB, Store};
use parking_lot::RwLock;
use std::mem;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use types::{BeaconState, EthSpec, Hash256};

// FIXME(michael): logging

pub struct Migrator<E: EthSpec> {
    db: Arc<RwLock<HotColdDB>>,
    tx: mpsc::Sender<(Hash256, BeaconState<E>)>,
    thread: thread::JoinHandle<()>,
}

impl<E: EthSpec> Migrator<E> {
    fn new(db: Arc<RwLock<HotColdDB>>) -> Self {
        let (tx, thread) = Self::spawn_thread(db.clone());

        Self { db, tx, thread }
    }

    fn freeze_to_state(&mut self, state_root: Hash256, state: BeaconState<E>) {
        if let Err(tx_err) = self.tx.send((state_root, state)) {
            let (tx, new_thread) = Self::spawn_thread(self.db.clone());

            self.tx = tx;
            let old_thread = mem::replace(&mut self.thread, new_thread);

            if let Err(thread_err) = old_thread.join() {
                eprintln!("Thread died: {:?}", thread_err);
            }

            let (state_root, state) = tx_err.0;
            self.freeze_to_state(state_root, state);
        }
    }

    fn spawn_thread(
        db: Arc<RwLock<HotColdDB>>,
    ) -> (
        mpsc::Sender<(Hash256, BeaconState<E>)>,
        thread::JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || {
            while let Ok((state_root, state)) = rx.recv() {
                if let Err(e) = HotColdDB::freeze_to_state(db.clone(), state_root, &state) {
                    eprintln!("Migration error: {:#?}", e);
                }
            }
        });

        (tx, thread)
    }
}
