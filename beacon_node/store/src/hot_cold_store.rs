use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::iter::StateRootsIterator;
use crate::{
    leveldb_store::LevelDB, DBColumn, Error, PartialBeaconState, SimpleStoreItem, Store, StoreItem,
};
use parking_lot::RwLock;
use slog::{info, trace, Logger};
use ssz::{Decode, Encode};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use types::*;

/// 32-byte key for accessing the `split_slot` of the freezer DB.
pub const SPLIT_SLOT_DB_KEY: &str = "FREEZERDBSPLITSLOTFREEZERDBSPLIT";

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
        if state.slot < self.get_split_slot() {
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
            if slot < self.get_split_slot() {
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
        _frozen_head_root: Hash256,
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

        let state_root_iter = StateRootsIterator::new(store.clone(), frozen_head);

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
        store.store_split_slot()?;

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
        let db = HotColdDB {
            split_slot: RwLock::new(Slot::new(0)),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            spec,
            log,
        };
        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly.
        if let Some(split_slot) = db.load_split_slot()? {
            *db.split_slot.write() = split_slot;
        }
        Ok(db)
    }

    pub fn store_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
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

        Ok(Some(state))
    }

    pub fn get_split_slot(&self) -> Slot {
        *self.split_slot.read()
    }

    fn load_split_slot(&self) -> Result<Option<Slot>, Error> {
        let key = Hash256::from_slice(SPLIT_SLOT_DB_KEY.as_bytes());
        let split_slot: Option<SplitSlot> = self.hot_db.get(&key)?;
        Ok(split_slot.map(|s| Slot::new(s.0)))
    }

    fn store_split_slot(&self) -> Result<(), Error> {
        let key = Hash256::from_slice(SPLIT_SLOT_DB_KEY.as_bytes());
        self.hot_db
            .put(&key, &SplitSlot(self.get_split_slot().as_u64()))?;
        Ok(())
    }
}

/// Struct for storing the split slot in the database.
#[derive(Clone, Copy)]
struct SplitSlot(u64);

impl SimpleStoreItem for SplitSlot {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(SplitSlot(u64::from_ssz_bytes(bytes)?))
    }
}
