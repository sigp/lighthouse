use crate::chunked_vector::{
    store_updated_vector, BlockRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::iter::{ParentRootBlockIterator, StateRootsIterator};
use crate::{
    leveldb_store::LevelDB, DBColumn, Error, PartialBeaconState, SimpleStoreItem, Store, StoreItem,
};
use parking_lot::RwLock;
use slog::{info, trace, warn, Logger};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
    SlotProcessingError,
};
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use types::*;

/// 32-byte key for accessing the `split_slot` of the freezer DB.
pub const SPLIT_SLOT_DB_KEY: &str = "FREEZERDBSPLITSLOTFREEZERDBSPLIT";

// FIXME(sproul): comments

pub struct HotColdDB {
    /// The slot and state root at the point where the database is split between hot and cold.
    ///
    /// Data for slots less than `split.slot` is in the cold DB, while data for slots
    /// greater than or equal is in the hot DB.
    split: RwLock<Split>,
    /// Number of slots per restore point state in the freezer database.
    slots_per_restore_point: u64,
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
    MissingRestorePointHash(u64),
    MissingRestorePoint(Hash256),
    MissingStateSlot(Hash256),
    MissingSplitState(Hash256, Slot),
    RestorePointDecodeError(ssz::DecodeError),
    RestorePointReplayFailure {
        expected_state_root: Hash256,
        observed_state_root: Hash256,
    },
    BlockReplayBeaconError(BeaconStateError),
    BlockReplaySlotError(SlotProcessingError),
    BlockReplayBlockError(BlockProcessingError),
    InvalidSlotsPerRestorePoint {
        slots_per_restore_point: u64,
        slots_per_historical_root: u64,
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
                self.load_archive_state(state_root, slot).map(Some)
            } else {
                self.hot_db.get_state(state_root, None)
            }
        } else {
            match self.hot_db.get_state(state_root, None)? {
                Some(state) => Ok(Some(state)),
                None => {
                    // Look-up the state in the freezer DB. We don't know the slot, so we must
                    // look it up separately and then use it to reconstruct the state from a
                    // restore point.
                    let slot = self.load_state_slot(state_root)?;
                    self.load_archive_state(state_root, slot).map(Some)
                }
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

        let state_root_iter = StateRootsIterator::new(store.clone(), frozen_head);

        let mut to_delete = vec![];
        for (state_root, slot) in
            state_root_iter.take_while(|&(_, slot)| slot >= current_split_slot)
        {
            if slot % store.slots_per_restore_point == 0 {
                trace!(store.log, "Freezing";
                   "slot" => slot,
                   "state_root" => format!("{}", state_root));

                let state: BeaconState<E> = match store.hot_db.get_state(&state_root, None)? {
                    Some(s) => s,
                    // If there's no state it could be a skip slot, which is fine, our job is just
                    // to move everything that was in the hot DB to the cold.
                    None => continue,
                };

                store.store_archive_state(&state_root, &state)?;
            }

            // Store a pointer from this state root to its slot, so we can later reconstruct states
            // from their state root alone.
            store.store_state_slot(&state_root, slot)?;

            to_delete.push(state_root);
        }

        // 2. Update the split slot
        *store.split.write() = Split {
            slot: frozen_head.slot,
            state_root: frozen_head_root,
        };
        store.store_split()?;

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
    pub fn open<E: EthSpec>(
        hot_path: &Path,
        cold_path: &Path,
        slots_per_restore_point: u64,
        spec: ChainSpec,
        log: Logger,
    ) -> Result<Self, Error> {
        Self::verify_slots_per_restore_point::<E>(slots_per_restore_point)?;

        let db = HotColdDB {
            split: RwLock::new(Split::default()),
            slots_per_restore_point,
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            spec,
            log,
        };
        // Load the previous split slot from the database (if any). This ensures we can
        // stop and restart correctly.
        if let Some(split) = db.load_split()? {
            *db.split.write() = split;
        }
        Ok(db)
    }

    pub fn store_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        if state.slot % self.slots_per_restore_point != 0 {
            warn!(
                self.log,
                "Not storing non-restore_point state in freezer";
                "slot" => state.slot.as_u64(),
                "state_root" => format!("{:?}", state_root)
            );
            return Ok(());
        }

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

        // 3. Store restore point.
        let restore_point_index = state.slot.as_u64() / self.slots_per_restore_point;
        self.store_restore_point_hash(restore_point_index, *state_root)?;

        Ok(())
    }

    pub fn load_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        slot: Slot,
    ) -> Result<BeaconState<E>, Error> {
        if slot.as_u64() % self.slots_per_restore_point == 0 {
            self.load_restore_point(state_root)
        } else {
            self.load_intermediate_state(state_root, slot)
        }
    }

    /// Load a restore point state by its `state_root`.
    fn load_restore_point<E: EthSpec>(
        &self,
        state_root: &Hash256,
    ) -> Result<BeaconState<E>, Error> {
        let mut partial_state = PartialBeaconState::db_get(&self.cold_db, state_root)?
            .ok_or_else(|| HotColdDbError::MissingRestorePoint(*state_root))?;

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;

        Ok(partial_state.try_into()?)
    }

    /// Load a restore point state by its `restore_point_index`.
    fn load_restore_point_by_index<E: EthSpec>(
        &self,
        restore_point_index: u64,
    ) -> Result<BeaconState<E>, Error> {
        let state_root = self
            .load_restore_point_hash(restore_point_index)?
            .ok_or(HotColdDbError::MissingRestorePointHash(restore_point_index))?;
        self.load_restore_point(&state_root)
    }

    /// Load a state that lies between restore points.
    fn load_intermediate_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        slot: Slot,
    ) -> Result<BeaconState<E>, Error> {
        // 1. Load the restore points either side of the intermediate state.
        let low_restore_point_idx = slot.as_u64() / self.slots_per_restore_point;
        let high_restore_point_idx = low_restore_point_idx + 1;

        // Acquire the read lock, so that the split can't change while this is happening.
        let split = self.split.read();

        let low_restore_point = self.load_restore_point_by_index(low_restore_point_idx)?;
        let high_restore_point = if high_restore_point_idx * self.slots_per_restore_point
            >= split.slot.as_u64()
        {
            self.get_state::<E>(&split.state_root, Some(split.slot))?
                .ok_or_else(|| HotColdDbError::MissingSplitState(split.state_root, split.slot))?
        } else {
            self.load_restore_point_by_index(high_restore_point_idx)?
        };

        // 2. Load the blocks from the high restore point back to the low restore point.
        let blocks = self.load_ancestor_blocks(
            low_restore_point.slot,
            slot,
            self.get_high_restore_point_block_root(&high_restore_point, slot),
        )?;

        // 3. Replay the blocks on top of the low restore point.
        let mut state = self.replay_blocks(low_restore_point, blocks, slot)?;

        // 4. Check that the state root is correct (should be quick).
        let observed_state_root = state.update_tree_hash_cache()?;

        if observed_state_root == *state_root {
            Ok(state)
        } else {
            Err(HotColdDbError::RestorePointReplayFailure {
                expected_state_root: *state_root,
                observed_state_root,
            }
            .into())
        }
    }

    fn get_high_restore_point_block_root<E: EthSpec>(
        &self,
        high_restore_point: &BeaconState<E>,
        slot: Slot,
    ) -> Hash256 {
        // FIXME(sproul): error handling?
        *high_restore_point
            .get_block_root(slot)
            .or_else(|_| high_restore_point.get_oldest_block_root())
            .expect("should always be able to get oldest block root")
    }

    fn load_ancestor_blocks<E: EthSpec>(
        &self,
        start_slot: Slot,
        end_slot: Slot,
        end_parent_hash: Hash256,
    ) -> Result<Vec<BeaconBlock<E>>, Error> {
        let mut blocks = ParentRootBlockIterator::new(self, end_parent_hash)
            .filter(|block| block.slot <= end_slot)
            // Exclude the block at the start slot, because it has already
            // been applied to the state
            .take_while(|block| block.slot > start_slot)
            .collect::<Vec<_>>();
        blocks.reverse();
        Ok(blocks)
    }

    fn replay_blocks<E: EthSpec>(
        &self,
        mut state: BeaconState<E>,
        blocks: Vec<BeaconBlock<E>>,
        target_slot: Slot,
    ) -> Result<BeaconState<E>, Error> {
        state
            .build_all_caches(&self.spec)
            .map_err(HotColdDbError::BlockReplayBeaconError)?;

        for block in blocks {
            while state.slot < block.slot {
                per_slot_processing(&mut state, &self.spec)
                    .map_err(HotColdDbError::BlockReplaySlotError)?;
            }
            per_block_processing(
                &mut state,
                &block,
                None,
                BlockSignatureStrategy::NoVerification,
                &self.spec,
            )
            .map_err(HotColdDbError::BlockReplayBlockError)?;
        }

        while state.slot < target_slot {
            per_slot_processing(&mut state, &self.spec)
                .map_err(HotColdDbError::BlockReplaySlotError)?;
        }

        Ok(state)
    }

    pub fn get_split_slot(&self) -> Slot {
        self.split.read().slot
    }

    fn load_split(&self) -> Result<Option<Split>, Error> {
        let key = Hash256::from_slice(SPLIT_SLOT_DB_KEY.as_bytes());
        let split: Option<Split> = self.hot_db.get(&key)?;
        Ok(split)
    }

    fn store_split(&self) -> Result<(), Error> {
        let key = Hash256::from_slice(SPLIT_SLOT_DB_KEY.as_bytes());
        self.hot_db.put(&key, &*self.split.read())?;
        Ok(())
    }

    fn load_restore_point_hash(&self, restore_point_index: u64) -> Result<Option<Hash256>, Error> {
        let key = Self::restore_point_key(restore_point_index);
        self.cold_db
            .get_bytes(DBColumn::BeaconRestorePoint.into(), &key)?
            .map(|bytes| Hash256::from_ssz_bytes(&bytes))
            .transpose()
            .map_err(HotColdDbError::RestorePointDecodeError)
            .map_err(Into::into)
    }

    fn store_restore_point_hash(
        &self,
        restore_point_index: u64,
        state_root: Hash256,
    ) -> Result<(), Error> {
        let key = Self::restore_point_key(restore_point_index);

        self.cold_db.put_bytes(
            DBColumn::BeaconRestorePoint.into(),
            &key,
            &state_root.as_ssz_bytes(),
        )?;
        Ok(())
    }

    fn restore_point_key(restore_point_index: u64) -> [u8; 8] {
        restore_point_index.to_be_bytes()
    }

    fn load_state_slot(&self, state_root: &Hash256) -> Result<Slot, Error> {
        StateSlot::db_get(&self.cold_db, state_root)?
            .map(|s| s.slot)
            .ok_or_else(|| HotColdDbError::MissingStateSlot(*state_root).into())
    }

    fn store_state_slot(&self, state_root: &Hash256, slot: Slot) -> Result<(), Error> {
        StateSlot::from(slot)
            .db_put(&self.cold_db, state_root)
            .map_err(Into::into)
    }

    /// Check that the restore point frequency is a divisor of the slots per historical root.
    ///
    /// This ensures that we have at least one restore point within range of our state
    /// root history when iterating backwards (and allows for more frequent restore points if
    /// desired).
    fn verify_slots_per_restore_point<E: EthSpec>(
        slots_per_restore_point: u64,
    ) -> Result<(), HotColdDbError> {
        let slots_per_historical_root = E::SlotsPerHistoricalRoot::to_u64();
        if slots_per_restore_point > 0 && slots_per_historical_root % slots_per_restore_point == 0 {
            Ok(())
        } else {
            Err(HotColdDbError::InvalidSlotsPerRestorePoint {
                slots_per_restore_point,
                slots_per_historical_root,
            })
        }
    }
}

/// Struct for storing the split slot and state root in the database.
#[derive(Clone, Copy, Default, Encode, Decode)]
struct Split {
    slot: Slot,
    state_root: Hash256,
}

impl SimpleStoreItem for Split {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Struct for storing the slot of a state root in the database.
#[derive(Clone, Copy, Default, Encode, Decode)]
struct StateSlot {
    slot: Slot,
}

impl From<Slot> for StateSlot {
    fn from(slot: Slot) -> Self {
        Self { slot }
    }
}

impl SimpleStoreItem for StateSlot {
    fn db_column() -> DBColumn {
        DBColumn::BeaconStateSlot
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
