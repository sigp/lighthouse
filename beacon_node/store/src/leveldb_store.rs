use super::*;
use crate::metrics;
use db_key::Key;
use leveldb::database::kv::KV;
use leveldb::database::Database;
use leveldb::error::Error as LevelDBError;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use std::path::Path;
use std::sync::Arc;

/// A wrapped leveldb database.
#[derive(Clone)]
pub struct LevelDB {
    // Note: this `Arc` is only included because of an artificial constraint by gRPC. Hopefully we
    // can remove this one day.
    db: Arc<Database<BytesKey>>,
}

impl LevelDB {
    /// Open a database at `path`, creating a new database if one does not already exist.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();

        options.create_if_missing = true;

        let db = Arc::new(Database::open(path, options)?);

        Ok(Self { db })
    }

    fn read_options(&self) -> ReadOptions<BytesKey> {
        ReadOptions::new()
    }

    fn write_options(&self) -> WriteOptions {
        WriteOptions::new()
    }

    fn get_key_for_col(col: &str, key: &[u8]) -> BytesKey {
        let mut col = col.as_bytes().to_vec();
        col.append(&mut key.to_vec());
        BytesKey { key: col }
    }
}

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

impl Store for LevelDB {
    /// Retrieve some bytes in `column` with `key`.
    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = Self::get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_READ_COUNT);

        let result = self
            .db
            .get(self.read_options(), column_key)
            .map_err(Into::into);

        if let Ok(Some(bytes)) = &result {
            metrics::inc_counter_by(&metrics::DISK_DB_READ_BYTES, bytes.len() as i64)
        }

        result
    }

    /// Store some `value` in `column`, indexed with `key`.
    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_WRITE_COUNT);
        metrics::inc_counter_by(&metrics::DISK_DB_WRITE_BYTES, val.len() as i64);

        self.db
            .put(self.write_options(), column_key, val)
            .map_err(Into::into)
    }

    /// Return `true` if `key` exists in `column`.
    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = Self::get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_EXISTS_COUNT);

        self.db
            .get(self.read_options(), column_key)
            .map_err(Into::into)
            .and_then(|val| Ok(val.is_some()))
    }

    /// Removes `key` from `column`.
    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);

        metrics::inc_counter(&metrics::DISK_DB_DELETE_COUNT);

        self.db
            .delete(self.write_options(), column_key)
            .map_err(Into::into)
    }
}

impl From<LevelDBError> for Error {
    fn from(e: LevelDBError) -> Error {
        Error::DBError {
            message: format!("{:?}", e),
        }
    }
}
