use crate::{
    ColumnIter, ColumnKeyIter, DBColumn, Error, ItemStore, Key, KeyValueStore, KeyValueStoreOp,
    errors::Error as DBError, get_key_for_col, hot_cold_store::BytesKey,
};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

type DBMap = BTreeMap<BytesKey, Vec<u8>>;

/// A thread-safe `BTreeMap` wrapper.
pub struct MemoryStore {
    db: RwLock<DBMap>,
    fault: AtomicBool,
    fault_armed: AtomicBool,
}

impl MemoryStore {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: RwLock::new(BTreeMap::new()),
            fault: AtomicBool::new(false),
            fault_armed: AtomicBool::new(false),
        }
    }

    /// Enable or disable fault injection.
    ///
    /// While enabled, every database read and write returns an error. This simulates a database
    /// suffering resource exhaustion (e.g. file descriptor exhaustion).
    pub fn inject_faults(&self, enabled: bool) {
        self.fault.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.fault_armed.store(false, Ordering::SeqCst);
        }
    }

    /// Set fault injection to trigger on the next batch that writes a block.
    ///
    /// Simulates resource exhaustion during a block write.
    pub fn inject_faults_on_next_block_write(&self) {
        self.fault_armed.store(true, Ordering::SeqCst);
    }

    fn check_fault(&self) -> Result<(), Error> {
        if self.fault.load(Ordering::SeqCst) {
            Err(Error::DBError {
                message: "Injected fault: too many open files".to_string(),
            })
        } else {
            Ok(())
        }
    }
}

impl KeyValueStore for MemoryStore {
    /// Get the value of some key from the database. Returns `None` if the key does not exist.
    fn get_bytes(&self, col: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.check_fault()?;
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        Ok(self.db.read().get(&column_key).cloned())
    }

    /// Puts a key in the database.
    fn put_bytes(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.check_fault()?;
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        self.db.write().insert(column_key, val.to_vec());
        Ok(())
    }

    fn put_bytes_sync(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes(col, key, val)
    }

    fn sync(&self) -> Result<(), Error> {
        // no-op
        Ok(())
    }

    /// Return true if some key exists in some column.
    fn key_exists(&self, col: DBColumn, key: &[u8]) -> Result<bool, Error> {
        self.check_fault()?;
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        Ok(self.db.read().contains_key(&column_key))
    }

    /// Delete some key from the database.
    fn key_delete(&self, col: DBColumn, key: &[u8]) -> Result<(), Error> {
        self.check_fault()?;
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        self.db.write().remove(&column_key);
        Ok(())
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        self.check_fault()?;
        if self.fault_armed.load(Ordering::SeqCst)
            && batch.iter().any(|op| {
                matches!(
                    op,
                    KeyValueStoreOp::PutKeyValue(DBColumn::BeaconBlock, _, _)
                )
            })
        {
            self.fault_armed.store(false, Ordering::SeqCst);
            self.fault.store(true, Ordering::SeqCst);
            return self.check_fault();
        }
        for op in batch {
            match op {
                KeyValueStoreOp::PutKeyValue(col, key, value) => {
                    let column_key = get_key_for_col(col, &key);
                    self.db
                        .write()
                        .insert(BytesKey::from_vec(column_key), value);
                }

                KeyValueStoreOp::DeleteKey(col, key) => {
                    let column_key = get_key_for_col(col, &key);
                    self.db.write().remove(&BytesKey::from_vec(column_key));
                }
            }
        }
        Ok(())
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
        // We use this awkward pattern because we can't lock the `self.db` field *and* maintain a
        // reference to the lock guard across calls to `.next()`. This would be require a
        // struct with a field (the iterator) which references another field (the lock guard).
        let start_key = BytesKey::from_vec(get_key_for_col(column, from));
        let keys = self
            .db
            .read()
            .range(start_key..)
            .take_while(|(k, _)| k.remove_column_variable(column).is_some())
            .filter_map(|(k, _)| k.remove_column_variable(column).map(|k| k.to_vec()))
            .collect::<Vec<_>>();
        Box::new(keys.into_iter().filter_map(move |key| {
            self.get_bytes(column, &key).transpose().map(|res| {
                let k = K::from_bytes(&key)?;
                let v = res?;
                Ok((k, v))
            })
        }))
    }

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        Box::new(self.iter_column(column).map(|res| res.map(|(k, _)| k)))
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        Ok(())
    }

    fn iter_column_keys_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnKeyIter<'_, K> {
        // We use this awkward pattern because we can't lock the `self.db` field *and* maintain a
        // reference to the lock guard across calls to `.next()`. This would be require a
        // struct with a field (the iterator) which references another field (the lock guard).
        let start_key = BytesKey::from_vec(get_key_for_col(column, from));
        let keys = self
            .db
            .read()
            .range(start_key..)
            .take_while(|(k, _)| k.remove_column_variable(column).is_some())
            .filter_map(|(k, _)| k.remove_column_variable(column).map(|k| k.to_vec()))
            .collect::<Vec<_>>();
        Box::new(keys.into_iter().map(move |key| K::from_bytes(&key)))
    }

    fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), DBError> {
        self.check_fault()?;
        for op in ops {
            let column_key = get_key_for_col(col, op);
            self.db.write().remove(&BytesKey::from_vec(column_key));
        }
        Ok(())
    }

    fn delete_if(
        &self,
        column: DBColumn,
        mut f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.check_fault()?;
        self.db.write().retain(|key, value| {
            if key.remove_column_variable(column).is_some() {
                !f(value).unwrap_or(false)
            } else {
                true
            }
        });
        Ok(())
    }
}

impl ItemStore for MemoryStore {}
