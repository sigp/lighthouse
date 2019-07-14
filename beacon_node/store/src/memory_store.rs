use super::{Error, Store};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

type DBHashMap = HashMap<Vec<u8>, Vec<u8>>;

/// A thread-safe `HashMap` wrapper.
#[derive(Clone)]
pub struct MemoryStore {
    // Note: this `Arc` is only included because of an artificial constraint by gRPC. Hopefully we
    // can remove this one day.
    db: Arc<RwLock<DBHashMap>>,
}

impl MemoryStore {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: Arc::new(RwLock::new(HashMap::new())),
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
}
