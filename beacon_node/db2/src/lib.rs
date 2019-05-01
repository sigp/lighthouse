// mod disk_db;
mod errors;
mod impls;
mod memory_db;

pub use self::memory_db::MemoryDB;
pub use errors::Error;
pub use types::*;
pub type DBValue = Vec<u8>;

pub trait Store: Sync + Send + Sized {
    fn put(&self, key: &Hash256, item: &impl StorableItem) -> Result<(), Error> {
        item.db_put(self, key)
    }

    fn get<I: StorableItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        I::db_get(self, key)
    }

    fn exists<I: StorableItem>(&self, key: &Hash256) -> Result<bool, Error> {
        I::db_exists(self, key)
    }

    fn delete<I: StorableItem>(&self, key: &Hash256) -> Result<(), Error> {
        I::db_delete(self, key)
    }

    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, Error>;

    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error>;

    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error>;

    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error>;
}

pub trait StoreEncode {
    fn as_store_bytes(&self) -> Vec<u8>;
}

pub trait StoreDecode: Sized {
    fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error>;
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

pub trait StorableItem: StoreEncode + StoreDecode + Sized {
    fn db_column() -> DBColumn;

    fn db_put(&self, store: &impl Store, key: &Hash256) -> Result<(), Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store
            .put_bytes(column, key, &self.as_store_bytes())
            .map_err(|e| e.into())
    }

    fn db_get(store: &impl Store, key: &Hash256) -> Result<Option<Self>, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        match store.get_bytes(column, key)? {
            Some(mut bytes) => Ok(Some(Self::from_store_bytes(&mut bytes[..])?)),
            None => Ok(None),
        }
    }

    fn db_exists(store: &impl Store, key: &Hash256) -> Result<bool, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store.key_exists(column, key)
    }

    fn db_delete(store: &impl Store, key: &Hash256) -> Result<(), Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store.key_delete(column, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{ssz_encode, Decodable};
    use ssz_derive::{Decode, Encode};

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct StorableThing {
        a: u64,
        b: u64,
    }

    impl StoreEncode for StorableThing {
        fn as_store_bytes(&self) -> Vec<u8> {
            ssz_encode(self)
        }
    }

    impl StoreDecode for StorableThing {
        fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error> {
            let (item, _) = Self::ssz_decode(bytes, 0)?;
            Ok(item)
        }
    }

    impl StorableItem for StorableThing {
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
