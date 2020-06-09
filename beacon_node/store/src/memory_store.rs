use super::{DBColumn, Error, ItemStore, KeyValueStore, Store, StoreOp};
use crate::forwards_iter::SimpleForwardsBlockRootsIterator;
use crate::hot_cold_store::HotStateSummary;
use crate::impls::beacon_state::{get_full_state, store_full_state};
use crate::StoreItem;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use types::*;

type DBHashMap = HashMap<Vec<u8>, Vec<u8>>;

/// A thread-safe `HashMap` wrapper.
pub struct MemoryStore<E: EthSpec> {
    db: RwLock<DBHashMap>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Clone for MemoryStore<E> {
    fn clone(&self) -> Self {
        Self {
            db: RwLock::new(self.db.read().clone()),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> MemoryStore<E> {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: RwLock::new(HashMap::new()),
            _phantom: PhantomData,
        }
    }

    fn get_key_for_col(col: &str, key: &[u8]) -> Vec<u8> {
        let mut col = col.as_bytes().to_vec();
        col.append(&mut key.to_vec());
        col
    }
}

impl<E: EthSpec> KeyValueStore<E> for MemoryStore<E> {
    /// Get the value of some key from the database. Returns `None` if the key does not exist.
    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = Self::get_key_for_col(col, key);

        Ok(self.db.read().get(&column_key).cloned())
    }

    /// Puts a key in the database.
    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);

        self.db.write().insert(column_key, val.to_vec());

        Ok(())
    }

    /// Return true if some key exists in some column.
    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = Self::get_key_for_col(col, key);

        Ok(self.db.read().contains_key(&column_key))
    }

    /// Delete some key from the database.
    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);

        self.db.write().remove(&column_key);

        Ok(())
    }

    fn do_atomically(&self, batch: &[StoreOp]) -> Result<(), Error> {
        for op in batch {
            match op {
                StoreOp::DeleteBlock(block_hash) => {
                    let untyped_hash: Hash256 = (*block_hash).into();
                    self.key_delete(DBColumn::BeaconBlock.into(), untyped_hash.as_bytes())?;
                }

                StoreOp::DeleteState(state_hash, slot) => {
                    let untyped_hash: Hash256 = (*state_hash).into();
                    if *slot % E::slots_per_epoch() == 0 {
                        self.key_delete(DBColumn::BeaconState.into(), untyped_hash.as_bytes())?;
                    } else {
                        self.key_delete(
                            DBColumn::BeaconStateSummary.into(),
                            untyped_hash.as_bytes(),
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl<E: EthSpec> ItemStore<E> for MemoryStore<E> {}

impl<E: EthSpec> Store<E> for MemoryStore<E> {
    type ForwardsBlockRootsIterator = SimpleForwardsBlockRootsIterator;

    fn put_block(&self, block_root: &Hash256, block: SignedBeaconBlock<E>) -> Result<(), Error> {
        self.put(block_root, &block)
    }

    fn get_block(&self, block_root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, Error> {
        self.get(block_root)
    }

    fn delete_block(&self, block_root: &Hash256) -> Result<(), Error> {
        self.key_delete(DBColumn::BeaconBlock.into(), block_root.as_bytes())
    }

    fn put_state_summary(
        &self,
        state_root: &Hash256,
        summary: HotStateSummary,
    ) -> Result<(), Error> {
        self.put(state_root, &summary).map_err(Into::into)
    }

    /// Store a state in the store.
    fn put_state(&self, state_root: &Hash256, state: &BeaconState<E>) -> Result<(), Error> {
        store_full_state(self, state_root, &state)
    }

    /// Fetch a state from the store.
    fn get_state(
        &self,
        state_root: &Hash256,
        _: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        get_full_state(self, state_root)
    }

    fn delete_state(&self, state_root: &Hash256, _slot: Slot) -> Result<(), Error> {
        self.key_delete(DBColumn::BeaconState.into(), state_root.as_bytes())
    }

    fn forwards_block_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        _: &ChainSpec,
    ) -> Result<Self::ForwardsBlockRootsIterator, Error> {
        SimpleForwardsBlockRootsIterator::new(store, start_slot, end_state, end_block_root)
    }

    /// Load the most recent ancestor state of `state_root` which lies on an epoch boundary.
    ///
    /// If `state_root` corresponds to an epoch boundary state, then that state itself should be
    /// returned.
    fn load_epoch_boundary_state(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<BeaconState<E>>, Error> {
        // The default implementation is not very efficient, but isn't used in prod.
        // See `HotColdDB` for the optimized implementation.
        if let Some(state) = self.get_state(state_root, None)? {
            let epoch_boundary_slot = state.slot / E::slots_per_epoch() * E::slots_per_epoch();
            if state.slot == epoch_boundary_slot {
                Ok(Some(state))
            } else {
                let epoch_boundary_state_root = state.get_state_root(epoch_boundary_slot)?;
                self.get_state(epoch_boundary_state_root, Some(epoch_boundary_slot))
            }
        } else {
            Ok(None)
        }
    }

    fn put_item<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        self.put(key, item)
    }

    fn get_item<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        self.get(key)
    }

    fn item_exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        self.exists::<I>(key)
    }

    fn do_atomically(&self, batch: &[StoreOp]) -> Result<(), Error> {
        KeyValueStore::do_atomically(self, batch)
    }
}
