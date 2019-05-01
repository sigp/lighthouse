// mod disk_db;
mod errors;
mod memory_db;

use db_encode::{db_encode, DBDecode, DBEncode};

pub use self::memory_db::MemoryDB;
pub use errors::Error;
pub use types::*;
pub type DBValue = Vec<u8>;

pub trait StoreDB: Sync + Send + Sized {
    fn put(&self, key: &Hash256, item: &impl DBRecord) -> Result<(), Error> {
        item.db_put(self, key)
    }

    fn get<I: DBRecord>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        I::db_get(self, key)
    }

    fn exists<I: DBRecord>(&self, key: &Hash256) -> Result<bool, Error> {
        I::db_exists(self, key)
    }

    fn delete<I: DBRecord>(&self, key: &Hash256) -> Result<(), Error> {
        I::db_delete(self, key)
    }

    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, Error>;

    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error>;

    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error>;

    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error>;
}

pub trait DBStore {
    fn db_column(&self) -> DBColumn;
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

    fn db_put(&self, store: &impl StoreDB, key: &Hash256) -> Result<(), Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store
            .put_bytes(column, key, &db_encode(self))
            .map_err(|e| e.into())
    }

    fn db_get(store: &impl StoreDB, key: &Hash256) -> Result<Option<Self>, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        match store.get_bytes(column, key)? {
            Some(bytes) => {
                let (item, _index) = Self::db_decode(&bytes, 0)?;
                Ok(Some(item))
            }
            None => Ok(None),
        }
    }

    fn db_exists(store: &impl StoreDB, key: &Hash256) -> Result<bool, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store.key_exists(column, key)
    }

    fn db_delete(store: &impl StoreDB, key: &Hash256) -> Result<(), Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store.key_delete(column, key)
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
    fn memorydb_can_store_and_retrieve() {
        let store = MemoryDB::open();

        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        store.put(&key, &item).unwrap();

        let retrieved = store.get(&key).unwrap().unwrap();

        assert_eq!(item, retrieved);
    }

    #[test]
    fn exists() {
        let store = MemoryDB::open();
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), true);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);
    }
}
