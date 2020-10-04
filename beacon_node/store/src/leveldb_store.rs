use super::*;
use crate::metrics;
use db_key::Key;
use leveldb::database::batch::{Batch, Writebatch};
use leveldb::database::kv::KV;
use leveldb::database::Database;
use leveldb::error::Error as LevelDBError;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use std::marker::PhantomData;
use std::path::Path;

/// A wrapped leveldb database.
pub struct LevelDB<E: EthSpec> {
    db: Database<BytesKey>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LevelDB<E> {
    /// Open a database at `path`, creating a new database if one does not already exist.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();

        options.create_if_missing = true;

        let db = Database::open(path, options)?;

        Ok(Self {
            db,
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
        metrics::inc_counter_by(&metrics::DISK_DB_WRITE_BYTES, val.len() as i64);
        let timer = metrics::start_timer(&metrics::DISK_DB_WRITE_TIMES);

        self.db
            .put(opts, BytesKey::from_vec(column_key), val)
            .map_err(Into::into)
            .map(|()| {
                metrics::stop_timer(timer);
            })
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
                    metrics::inc_counter_by(&metrics::DISK_DB_READ_BYTES, bytes.len() as i64);
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
}

impl<E: EthSpec> ItemStore<E> for LevelDB<E> {}

/// Used for keying leveldb.
pub struct BytesKey {
    key: Vec<u8>,
}

impl Key for BytesKey {
    fn from_u8(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(self.key.as_slice())
    }
}

impl BytesKey {
    fn from_vec(key: Vec<u8>) -> Self {
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
