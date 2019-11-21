use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::iter::{ReverseStateRootIterator, StateRootsIterator};
use crate::{leveldb_store::LevelDB, DBColumn, Error, PartialBeaconState, Store, StoreItem};
use parking_lot::RwLock;
use slog::crit;
use slog::{info, trace, Logger};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use types::*;

pub struct HotColdDB {
    /// The slot before which all data is stored in the cold database.
    ///
    /// Data for slots less than `split_slot` is in the cold DB, while data for slots
    /// greater than or equal is in the hot DB.
    split_slot: RwLock<Slot>,
    /// Cold database containing compact historical data.
    cold_db: LevelDB,
    /// Hot database containing duplicated but quick-to-access recent data.
    hot_db: LevelDB,
    /// Chain spec.
    spec: ChainSpec,
    /// Logger.
    pub(crate) log: Logger,
}

#[derive(Debug, PartialEq)]
pub enum HotColdDbError {
    FreezeSlotError {
        current_split_slot: Slot,
        proposed_split_slot: Slot,
    },
}

impl Store for HotColdDB {
    // Defer to the hot database for basic operations (including blocks for now)
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.hot_db.get_bytes(column, key)
    }

    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.hot_db.put_bytes(column, key, value)
    }

    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error> {
        self.hot_db.key_exists(column, key)
    }

    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error> {
        self.hot_db.key_delete(column, key)
    }

    /// Store a state in the store.
    fn put_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // FIXME(sproul): change back to <
        if state.slot <= self.get_split_slot() {
            self.store_archive_state(state_root, state)
        } else {
            self.hot_db.put_state(state_root, state)
        }
    }

    /// Fetch a state from the store.
    fn get_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        if let Some(slot) = slot {
            // FIXME(sproul): change back to <
            if slot <= self.get_split_slot() {
                self.load_archive_state(state_root)
            } else {
                self.hot_db.get_state(state_root, None)
            }
        } else {
            match self.hot_db.get_state(state_root, None)? {
                Some(state) => Ok(Some(state)),
                None => self.load_archive_state(state_root),
            }
        }
    }

    fn freeze_to_state<E: EthSpec>(
        store: Arc<Self>,
        frozen_head_root: Hash256,
        frozen_head: &BeaconState<E>,
    ) -> Result<(), Error> {
        info!(
            store.log,
            "Freezer migration started";
            "slot" => frozen_head.slot
        );

        // 1. Copy all of the states between the head and the split slot, from the hot DB
        // to the cold DB.
        let current_split_slot = store.get_split_slot();

        if frozen_head.slot < current_split_slot {
            Err(HotColdDbError::FreezeSlotError {
                current_split_slot,
                proposed_split_slot: frozen_head.slot,
            })?;
        }

        let state_root_iter = {
            let iter = StateRootsIterator::new(store.clone(), frozen_head);
            ReverseStateRootIterator::new((frozen_head_root, frozen_head.slot), iter)
        };

        let mut to_delete = vec![];
        for (state_root, slot) in
            state_root_iter.take_while(|&(_, slot)| slot >= current_split_slot)
        {
            trace!(store.log, "Freezing";
                   "slot" => slot,
                   "state_root" => format!("{}", state_root));

            let state: BeaconState<E> = match store.hot_db.get_state(&state_root, None)? {
                Some(s) => s,
                // If there's no state it could be a skip slot, which is fine, our job is just
                // to move everything that was in the hot DB to the cold.
                None => continue,
            };

            to_delete.push(state_root);

            store.store_archive_state(&state_root, &state)?;
        }

        // 2. Update the split slot
        *store.split_slot.write() = frozen_head.slot;

        // 3. Delete from the hot DB
        for state_root in to_delete {
            store
                .hot_db
                .key_delete(DBColumn::BeaconState.into(), state_root.as_bytes())?;
        }

        info!(
            store.log,
            "Freezer migration complete";
            "slot" => frozen_head.slot
        );

        Ok(())
    }
}

impl HotColdDB {
    pub fn open(
        hot_path: &Path,
        cold_path: &Path,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, Error> {
        Ok(HotColdDB {
            split_slot: RwLock::new(Slot::new(0)),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            spec,
            log,
        })
    }

    pub fn store_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // FIXME(sproul) Change to trace
        trace!(
            self.log,
            "Freezing state";
            "slot" => state.slot.as_u64(),
            "state_root" => format!("{:?}", state_root)
        );
        // 1. Convert to PartialBeaconState and store that in the DB.
        let partial_state = PartialBeaconState::from_state_forgetful(state);
        partial_state.db_put(&self.cold_db, state_root)?;

        // 2. Store updated vector entries.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec)?;
        store_updated_vector(StateRoots, db, state, &self.spec)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec)?;

        Ok(())
    }

    pub fn load_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<BeaconState<E>>, Error> {
        let mut partial_state = match PartialBeaconState::db_get(&self.cold_db, state_root)? {
            Some(s) => s,
            None => return Ok(None),
        };

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;

        let state: BeaconState<E> = partial_state.try_into()?;

        println!("Loaded archive state for {:?}\n{:#?}", state_root, state);

        // #[cfg(paranoid)]
        let db_state_root = state.canonical_root();
        if &db_state_root != state_root {
            crit!(
                self.log,
                "State from freezer has incorrect hash";
                "expected" => format!("{:?}", state_root),
                "observed" => format!("{:?}", db_state_root)
            );
        }

        Ok(Some(state))
    }

    pub fn get_split_slot(&self) -> Slot {
        *self.split_slot.read()
    }
}
