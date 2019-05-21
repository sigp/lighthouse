// mod disk_db;
mod block_at_slot;
mod errors;
mod impls;
mod leveldb_store;
mod memory_db;

pub use self::leveldb_store::LevelDB;
pub use self::memory_db::MemoryDB;
pub use errors::Error;
pub use types::*;
pub type DBValue = Vec<u8>;

pub trait Store: Sync + Send + Sized {
    fn put(&self, key: &Hash256, item: &impl StoreItem) -> Result<(), Error> {
        item.db_put(self, key)
    }

    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        I::db_get(self, key)
    }

    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        I::db_exists(self, key)
    }

    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        I::db_delete(self, key)
    }

    fn get_block_at_preceeding_slot(
        &self,
        start_block_root: Hash256,
        slot: Slot,
    ) -> Result<Option<(Hash256, BeaconBlock)>, Error> {
        block_at_slot::get_block_at_preceeding_slot(self, slot, start_block_root)
    }

    fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, Error>;

    fn put_bytes(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), Error>;

    fn key_exists(&self, col: &str, key: &[u8]) -> Result<bool, Error>;

    fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error>;
}

pub enum DBColumn {
    BeaconBlock,
    BeaconState,
    BeaconChain,
}

impl<'a> Into<&'a str> for DBColumn {
    /// Returns a `&str` that can be used for keying a key-value data base.
    fn into(self) -> &'a str {
        match self {
            DBColumn::BeaconBlock => &"blk",
            DBColumn::BeaconState => &"ste",
            DBColumn::BeaconChain => &"bch",
        }
    }
}

pub trait StoreItem: Sized {
    fn db_column() -> DBColumn;

    fn as_store_bytes(&self) -> Vec<u8>;

    fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error>;

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
    use ssz::{Decode, Encode};
    use ssz_derive::{Decode, Encode};
    use tempfile::tempdir;

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct StorableThing {
        a: u64,
        b: u64,
    }

    impl StoreItem for StorableThing {
        fn db_column() -> DBColumn {
            DBColumn::BeaconBlock
        }

        fn as_store_bytes(&self) -> Vec<u8> {
            self.as_ssz_bytes()
        }

        fn from_store_bytes(bytes: &mut [u8]) -> Result<Self, Error> {
            Self::from_ssz_bytes(bytes).map_err(Into::into)
        }
    }

    #[test]
    fn leveldb_can_store_and_retrieve() {
        let dir = tempdir().unwrap();
        let path = dir.path();

        let store = LevelDB::open(&path).unwrap();

        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        store.put(&key, &item).unwrap();

        let retrieved = store.get(&key).unwrap().unwrap();

        assert_eq!(item, retrieved);
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
