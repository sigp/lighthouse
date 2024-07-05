use super::*;
use crate::hot_cold_store::HotColdDBError;
use leveldb::compaction::Compaction;
use leveldb::database::batch::{Batch, Writebatch};
use leveldb::database::kv::KV;
use leveldb::database::Database;
use leveldb::error::Error as LevelDBError;
use leveldb::iterator::{Iterable, KeyIterator, LevelDBIterator};
use leveldb::options::{Options, ReadOptions, WriteOptions};
use parking_lot::Mutex;
use std::marker::PhantomData;
use std::path::Path;

/// A wrapped leveldb database.
pub struct LevelDB<E: EthSpec> {
    db: Database<BytesKey>,
    /// A mutex to synchronise sensitive read-write transactions.
    transaction_mutex: Mutex<()>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LevelDB<E> {
    /// Open a database at `path`, creating a new database if one does not already exist.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();

        options.create_if_missing = true;

        let db = Database::open(path, options)?;
        let transaction_mutex = Mutex::new(());

        Ok(Self {
            db,
            transaction_mutex,
            _phantom: PhantomData,
        })
    }

    fn read_options(&self) -> ReadOptions<BytesKey> {
        ReadOptions::new()
    }

    fn write_options(&self) -> WriteOptions {
        WriteOptions::new()
    }

    fn write_options_sync(&self) -> WriteOptions {
        let mut opts = WriteOptions::new();
        opts.sync = true;
        opts
    }

    fn put_bytes_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions,
    ) -> Result<(), Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_WRITE_COUNT);
        metrics::inc_counter_by(&metrics::DISK_DB_WRITE_BYTES, val.len() as u64);
        let timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);

        self.db
            .put(opts, BytesKey::from_vec(column_key), val)
            .map_err(Into::into)
            .map(|()| {
                metrics::stop_timer(timer);
            })
    }

    pub fn keys_iter(&self) -> KeyIterator<BytesKey> {
        self.db.keys_iter(self.read_options())
    }
}

impl<E: EthSpec> KeyValueStore<E> for LevelDB<E> {
    /// Store some `value` in `column`, indexed with `key`.
    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options())
    }

    fn put_bytes_sync(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes_with_options(col, key, val, self.write_options_sync())
    }

    fn sync(&self) -> Result<(), Error> {
        self.put_bytes_sync("sync", b"sync", b"sync")
    }

    /// Retrieve some bytes in `column` with `key`.
    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_READ_COUNT);
        let timer = metrics::start_timer(&metrics::DISK_DB_READ_TIMES);

        self.db
            .get(self.read_options(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
            .map(|opt| {
                opt.map(|bytes| {
                    metrics::inc_counter_by(&metrics::DISK_DB_READ_BYTES, bytes.len() as u64);
                    metrics::stop_timer(timer);
                    bytes
                })
            })
    }

    /// Return `true` if `key` exists in `column`.
    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_EXISTS_COUNT);

        self.db
            .get(self.read_options(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
            .map(|val| val.is_some())
    }

    /// Removes `key` from `column`.
    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_DELETE_COUNT);

        self.db
            .delete(self.write_options(), BytesKey::from_vec(column_key))
            .map_err(Into::into)
    }

    fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        let mut leveldb_batch = Writebatch::new();
        for op in ops_batch {
            match op {
                KeyValueStoreOp::PutKeyValue(key, value) => {
                    leveldb_batch.put(BytesKey::from_vec(key), &value);
                }

                KeyValueStoreOp::DeleteKey(key) => {
                    leveldb_batch.delete(BytesKey::from_vec(key));
                }
            }
        }
        self.db.write(self.write_options(), &leveldb_batch)?;
        Ok(())
    }

    fn begin_rw_transaction(&self) -> MutexGuard<()> {
        self.transaction_mutex.lock()
    }

    fn compact_column(&self, column: DBColumn) -> Result<(), Error> {
        // Use key-size-agnostic keys [] and 0xff..ff with a minimum of 32 bytes to account for
        // columns that may change size between sub-databases or schema versions.
        let start_key = BytesKey::from_vec(get_key_for_col(column.as_str(), &[]));
        let end_key = BytesKey::from_vec(get_key_for_col(
            column.as_str(),
            &vec![0xff; std::cmp::max(column.key_size(), 32)],
        ));
        self.db.compact(&start_key, &end_key);
        Ok(())
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<K> {
        let start_key = BytesKey::from_vec(get_key_for_col(column.into(), from));

        let iter = self.db.iter(self.read_options());
        iter.seek(&start_key);

        Box::new(
            iter.take_while(move |(key, _)| key.matches_column(column))
                .map(move |(bytes_key, value)| {
                    let key = bytes_key.remove_column_variable(column).ok_or_else(|| {
                        HotColdDBError::IterationError {
                            unexpected_key: bytes_key.clone(),
                        }
                    })?;
                    Ok((K::from_bytes(key)?, value))
                }),
        )
    }

    fn iter_raw_entries(&self, column: DBColumn, prefix: &[u8]) -> RawEntryIter {
        let start_key = BytesKey::from_vec(get_key_for_col(column.into(), prefix));

        let iter = self.db.iter(self.read_options());
        iter.seek(&start_key);

        Box::new(
            iter.take_while(move |(key, _)| key.key.starts_with(start_key.key.as_slice()))
                .map(move |(bytes_key, value)| {
                    let subkey = &bytes_key.key[column.as_bytes().len()..];
                    Ok((Vec::from(subkey), value))
                }),
        )
    }

    fn iter_raw_keys(&self, column: DBColumn, prefix: &[u8]) -> RawKeyIter {
        let start_key = BytesKey::from_vec(get_key_for_col(column.into(), prefix));

        let iter = self.db.keys_iter(self.read_options());
        iter.seek(&start_key);

        Box::new(
            iter.take_while(move |key| key.key.starts_with(start_key.key.as_slice()))
                .map(move |bytes_key| {
                    let subkey = &bytes_key.key[column.as_bytes().len()..];
                    Ok(Vec::from(subkey))
                }),
        )
    }

    /// Iterate through all keys and values in a particular column.
    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<K> {
        let start_key =
            BytesKey::from_vec(get_key_for_col(column.into(), &vec![0; column.key_size()]));

        let iter = self.db.keys_iter(self.read_options());
        iter.seek(&start_key);

        Box::new(
            iter.take_while(move |key| key.matches_column(column))
                .map(move |bytes_key| {
                    let key = bytes_key.remove_column_variable(column).ok_or_else(|| {
                        HotColdDBError::IterationError {
                            unexpected_key: bytes_key.clone(),
                        }
                    })?;
                    K::from_bytes(key)
                }),
        )
    }
}

impl<E: EthSpec> ItemStore<E> for LevelDB<E> {}

/// Used for keying leveldb.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BytesKey {
    key: Vec<u8>,
}

impl db_key::Key for BytesKey {
    fn from_u8(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(self.key.as_slice())
    }
}

impl BytesKey {
    /// Return `true` iff this `BytesKey` was created with the given `column`.
    pub fn matches_column(&self, column: DBColumn) -> bool {
        self.key.starts_with(column.as_bytes())
    }

    /// Remove the column from a 32 byte key, yielding the `Hash256` key.
    pub fn remove_column(&self, column: DBColumn) -> Option<Hash256> {
        let key = self.remove_column_variable(column)?;
        (column.key_size() == 32).then(|| Hash256::from_slice(key))
    }

    /// Remove the column from a key.
    ///
    /// Will return `None` if the value doesn't match the column or has the wrong length.
    pub fn remove_column_variable(&self, column: DBColumn) -> Option<&[u8]> {
        if self.matches_column(column) {
            let subkey = &self.key[column.as_bytes().len()..];
            if subkey.len() == column.key_size() {
                return Some(subkey);
            }
        }
        None
    }

    pub fn from_vec(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl From<LevelDBError> for Error {
    fn from(e: LevelDBError) -> Error {
        Error::DBError {
            message: format!("{:?}", e),
        }
    }
}
