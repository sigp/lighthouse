use super::*;
use db_key::Key;
use leveldb::database::kv::KV;
use leveldb::database::Database;
use leveldb::error::Error as LevelDBError;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use std::path::Path;

pub struct LevelDB {
    db: Database<BytesKey>,
}

impl LevelDB {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();

        options.create_if_missing = true;

        let db = Database::open(path, options)?;

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
    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, Error> {
        let column_key = Self::get_key_for_col(col, key);

        self.db
            .get(self.read_options(), column_key)
            .map_err(Into::into)
    }

    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);

        self.db
            .put(self.write_options(), column_key, val)
            .map_err(Into::into)
    }

    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error> {
        let column_key = Self::get_key_for_col(col, key);

        self.db
            .get(self.read_options(), column_key)
            .map_err(Into::into)
            .and_then(|val| Ok(val.is_some()))
    }

    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        let column_key = Self::get_key_for_col(col, key);
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
