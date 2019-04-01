extern crate blake2_rfc as blake2;
extern crate bls;
extern crate rocksdb;

mod disk_db;
mod memory_db;
pub mod stores;
mod traits;

use self::stores::COLUMNS;
use db_encode::{db_encode, DBDecode, DBEncode};
use ssz::DecodeError;
use std::sync::Arc;

pub use self::disk_db::DiskDB;
pub use self::memory_db::MemoryDB;
pub use self::traits::{ClientDB, DBError, DBValue};
pub use types::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    SszDecodeError(DecodeError),
    DBError { message: String },
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::SszDecodeError(e)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError { message: e.message }
    }
}

/// Currently available database options
#[derive(Debug, Clone)]
pub enum DBType {
    Memory,
    RocksDB,
}

pub enum DBColumn {
    Block,
    State,
    BeaconChain,
}

impl<'a> Into<&'a str> for DBColumn {
    /// Returns a `&str` that can be used for keying a key-value data base.
    fn into(self) -> &'a str {
        match self {
            DBColumn::Block => &"blk",
            DBColumn::State => &"ste",
            DBColumn::BeaconChain => &"bch",
        }
    }
}

pub trait DBRecord: DBEncode + DBDecode {
    fn db_column() -> DBColumn;
}

pub struct Store<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

impl Store<MemoryDB> {
    fn new_in_memory() -> Self {
        Self {
            db: Arc::new(MemoryDB::open()),
        }
    }
}

impl<T> Store<T>
where
    T: ClientDB,
{
    /// Put `item` in the store as `key`.
    ///
    /// The `item` must implement `DBRecord` which defines the db column used.
    fn put<I>(&self, key: &Hash256, item: &I) -> Result<(), Error>
    where
        I: DBRecord,
    {
        let column = I::db_column().into();
        let key = key.as_bytes();
        let val = db_encode(item);

        self.db.put(column, key, &val).map_err(|e| e.into())
    }

    /// Retrieves an `Ok(Some(item)` from the store if `key` exists, otherwise returns `Ok(None)`.
    ///
    /// The `item` must implement `DBRecord` which defines the db column used.
    fn get<I>(&self, key: &Hash256) -> Result<Option<I>, Error>
    where
        I: DBRecord,
    {
        let column = I::db_column().into();
        let key = key.as_bytes();

        match self.db.get(column, key)? {
            Some(bytes) => {
                let (item, _index) = I::db_decode(&bytes, 0)?;
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use db_encode_derive::{DBDecode, DBEncode};
    use ssz::Decodable;
    use ssz_derive::{Decode, Encode};

    #[derive(PartialEq, Debug, Encode, Decode, DBEncode, DBDecode)]
    struct StorableThing {
        a: u64,
        b: u64,
    }

    impl DBRecord for StorableThing {
        fn db_column() -> DBColumn {
            DBColumn::Block
        }
    }

    #[test]
    fn memorydb_can_store() {
        let store = Store::new_in_memory();

        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        store.put(&key, &item).unwrap();

        let retrieved = store.get(&key).unwrap().unwrap();

        assert_eq!(item, retrieved);
    }
}
