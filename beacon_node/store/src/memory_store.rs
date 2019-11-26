use super::{Error, Store};
use crate::impls::beacon_state::{get_full_state, store_full_state};
use parking_lot::RwLock;
use std::collections::HashMap;
use types::*;

type DBHashMap = HashMap<Vec<u8>, Vec<u8>>;

/// A thread-safe `HashMap` wrapper.
pub struct MemoryStore {
    db: RwLock<DBHashMap>,
}

impl Clone for MemoryStore {
    fn clone(&self) -> Self {
        Self {
            db: RwLock::new(self.db.read().clone()),
        }
    }
}

impl MemoryStore {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: RwLock::new(HashMap::new()),
        }
    }

    fn get_key_for_col(col: &str, key: &[u8]) -> Vec<u8> {
        let mut col = col.as_bytes().to_vec();
        col.append(&mut key.to_vec());
        col
    }
}

impl Store for MemoryStore {
    /// Get the value of some key from the database. Returns `None` if the key does not exist.
    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = MemoryStore::get_key_for_col(col, key);

        Ok(self
            .db
            .read()
            .get(&column_key)
            .and_then(|val| Some(val.clone())))
    }

    /// Puts a key in the database.
    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        let column_key = MemoryStore::get_key_for_col(col, key);

        self.db.write().insert(column_key, val.to_vec());

        Ok(())
    }

    /// Return true if some key exists in some column.
    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = MemoryStore::get_key_for_col(col, key);

        Ok(self.db.read().contains_key(&column_key))
    }

    /// Delete some key from the database.
    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = MemoryStore::get_key_for_col(col, key);

        self.db.write().remove(&column_key);

        Ok(())
    }

    /// Store a state in the store.
    fn put_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        store_full_state(self, state_root, state)
    }

    /// Fetch a state from the store.
    fn get_state<E: EthSpec>(
        &self,
        state_root: &Hash256,
        _: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error> {
        get_full_state(self, state_root)
    }
}
