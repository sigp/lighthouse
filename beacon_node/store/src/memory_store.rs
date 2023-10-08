use super::{Error, ItemStore, KeyValueStore, KeyValueStoreOp};
use crate::{ColumnIter, DBColumn};
use parking_lot::{Mutex, MutexGuard, RwLock};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use types::*;

type DBHashMap = HashMap<Vec<u8>, Vec<u8>>;
type DBKeyMap = HashMap<Vec<u8>, HashSet<Vec<u8>>>;

/// A thread-safe `HashMap` wrapper.
pub struct MemoryStore<E: EthSpec> {
    db: RwLock<DBHashMap>,
    col_keys: RwLock<DBKeyMap>,
    transaction_mutex: Mutex<()>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> MemoryStore<E> {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: RwLock::new(HashMap::new()),
            col_keys: RwLock::new(HashMap::new()),
            transaction_mutex: Mutex::new(()),
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
        self.col_keys
            .write()
            .entry(col.as_bytes().to_vec())
            .or_default()
            .insert(key.to_vec());
        Ok(())
    }

    fn put_bytes_sync(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes(col, key, val)
    }

    fn sync(&self) -> Result<(), Error> {
        // no-op
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
        self.col_keys
            .write()
            .get_mut(&col.as_bytes().to_vec())
            .map(|set| set.remove(key));
        Ok(())
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        for op in batch {
            match op {
                KeyValueStoreOp::PutKeyValue(key, value) => {
                    self.db.write().insert(key, value);
                }

                KeyValueStoreOp::DeleteKey(hash) => {
                    self.db.write().remove(&hash);
                }
            }
        }
        Ok(())
    }

    // pub type ColumnIter<'a> = Box<dyn Iterator<Item = Result<(Hash256, Vec<u8>), Error>> + 'a>;
    fn iter_column(&self, column: DBColumn) -> ColumnIter {
        let col = column.as_str();
        if let Some(keys) = self
            .col_keys
            .read()
            .get(col.as_bytes())
            .map(|set| set.iter().cloned().collect::<Vec<_>>())
        {
            Box::new(keys.into_iter().filter_map(move |key| {
                let hash = Hash256::from_slice(&key);
                self.get_bytes(col, &key)
                    .transpose()
                    .map(|res| res.map(|bytes| (hash, bytes)))
            }))
        } else {
            Box::new(std::iter::empty())
        }
    }

    fn begin_rw_transaction(&self) -> MutexGuard<()> {
        self.transaction_mutex.lock()
    }

    fn compact(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl<E: EthSpec> ItemStore<E> for MemoryStore<E> {}
