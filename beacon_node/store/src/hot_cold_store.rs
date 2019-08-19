use crate::chunked_vector::{
    store_updated_vector, ActiveIndexRoots, BlockRoots, CompactCommitteesRoots, HistoricalRoots,
    RandaoMixes, StateRoots,
};
use crate::iter::AncestorIter;
use crate::{leveldb_store::LevelDB, DBColumn, Error, PartialBeaconState, Store, StoreItem};
use parking_lot::RwLock;
use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;
use types::*;

// FIXME(michael): this probably shouldn't need to be clone?
#[derive(Clone)]
pub struct HotColdDB {
    /// The slot before which all data is stored in the cold database.
    ///
    /// Data for slots less than `split_slot` is in the cold DB, while data for slots
    /// greater than or equal is in the hot DB.
    split_slot: Slot,
    /// Cold database containing compact historical data.
    cold_db: LevelDB,
    /// Hot database containing duplicated but quick-to-access recent data.
    hot_db: LevelDB,
    /// Chain spec.
    spec: Arc<ChainSpec>,
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
        if state.slot < self.split_slot {
            println!("Storing at state at slot {} in the archival DB", state.slot);
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
        println!("Getting a state from slot {:?}", slot);
        if let Some(slot) = slot {
            if slot < self.split_slot {
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
        store: Arc<RwLock<Self>>,
        frozen_head: &BeaconState<E>,
    ) -> Result<(), Error> {
        // 1. Copy all of the states between the head and the split slot from the hot DB
        // to the cold DB.
        let reader = store.read();
        let current_split_slot = reader.split_slot;

        // FIXME(michael): make this an error
        if frozen_head.slot <= current_split_slot {
            panic!(
                "can't decrease split slot: new slot {} <= existing slot {}",
                frozen_head.slot, current_split_slot
            );
        }

        // TODO(michael): optimise for skipped slots
        // FIXME(michael): raise errors
        let mut to_delete = vec![];
        for (state_root, slot) in frozen_head
            .try_iter_ancestor_roots(store.clone())
            .expect("BeaconState roots iterator is always Some")
            .take_while(|&(_, slot)| slot >= current_split_slot)
        {
            println!("Freezing state at slot {} ({:?})", slot, state_root);
            let state: BeaconState<E> = match reader.hot_db.get_state(&state_root, None)? {
                Some(s) => s,
                // FIXME(michael): this is how we handle skip slots
                None => continue,
            };

            to_delete.push(state_root);

            reader
                .store_archive_state(&state_root, &state)
                .expect("work bitch!");
        }

        drop(reader);

        // 2. Update the split slot
        store.write().split_slot = dbg!(frozen_head.slot + 1);

        // 3. Delete from the hot DB
        let reader = store.read();
        for state_root in to_delete {
            reader
                .hot_db
                .key_delete(DBColumn::BeaconState.into(), state_root.as_bytes())?;
        }

        Ok(())
    }
}

impl HotColdDB {
    pub fn open(hot_path: &Path, cold_path: &Path, spec: Arc<ChainSpec>) -> Result<Self, Error> {
        Ok(HotColdDB {
            split_slot: Slot::new(0),
            cold_db: LevelDB::open(cold_path)?,
            hot_db: LevelDB::open(hot_path)?,
            spec,
        })
    }

    pub fn store_archive_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // 1. Convert to PartialBeaconState and store that in the DB.
        let partial_state = PartialBeaconState::from_state_forgetful(state);
        partial_state.db_put(&self.cold_db, state_root)?;

        // 2. Store updated vector entries.
        let db = &self.cold_db;
        store_updated_vector(BlockRoots, db, state, &self.spec)?;
        store_updated_vector(StateRoots, db, state, &self.spec)?;
        store_updated_vector(HistoricalRoots, db, state, &self.spec)?;
        store_updated_vector(RandaoMixes, db, state, &self.spec)?;
        store_updated_vector(ActiveIndexRoots, db, state, &self.spec)?;
        store_updated_vector(CompactCommitteesRoots, db, state, &self.spec)?;

        // FIXME(michael): debugging
        use compare_fields::{CompareFields, Comparison, FieldComparison};
        let mut stored_state = self
            .load_archive_state(state_root)
            .expect("just stored")
            .expect("valid state");

        stored_state
            .build_all_caches(&self.spec)
            .expect("cache should build");

        let mut full_state = state.clone();
        full_state
            .build_all_caches(&self.spec)
            .expect("cache should build");

        let mut mismatching_fields: Vec<Comparison> = full_state
            .compare_fields(&stored_state)
            .into_iter()
            .filter(Comparison::not_equal)
            .collect();

        mismatching_fields
            .iter_mut()
            .for_each(|f| f.retain_children(FieldComparison::not_equal));

        if !mismatching_fields.is_empty() {
            println!(
                "Fields not equal (a = actual, b = stored): {:#?}",
                mismatching_fields
            );
            assert!(false);
        }

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

        println!(
            "Loading archive state at slot {}: {:?}",
            partial_state.slot, state_root
        );

        // Fill in the fields of the partial state.
        partial_state.load_block_roots(&self.cold_db, &self.spec)?;
        partial_state.load_state_roots(&self.cold_db, &self.spec)?;
        partial_state.load_historical_roots(&self.cold_db, &self.spec)?;
        partial_state.load_randao_mixes(&self.cold_db, &self.spec)?;
        partial_state.load_active_index_roots(&self.cold_db, &self.spec)?;
        partial_state.load_compact_committees_roots(&self.cold_db, &self.spec)?;

        let state: BeaconState<E> = partial_state.try_into()?;

        Ok(Some(state))
    }
}

mod test {}
