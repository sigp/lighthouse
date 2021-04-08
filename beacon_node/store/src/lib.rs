//! Storage functionality for Lighthouse.
//!
//! Provides the following stores:
//!
//! - `HotColdDB`: an on-disk store backed by leveldb. Used in production.
//! - `MemoryStore`: an in-memory store backed by a hash-map. Used for testing.
//!
//! Provides a simple API for storing/retrieving all types that sometimes needs type-hints. See
//! tests for implementation examples.
#[macro_use]
extern crate lazy_static;

pub mod chunked_iter;
pub mod chunked_vector;
pub mod config;
pub mod errors;
mod forwards_iter;
mod garbage_collection;
pub mod hot_cold_store;
mod impls;
mod leveldb_store;
mod memory_store;
pub mod metadata;
pub mod metrics;
mod partial_beacon_state;

pub mod iter;

pub use self::config::StoreConfig;
pub use self::hot_cold_store::{BlockReplay, HotColdDB, HotStateSummary, Split};
pub use self::leveldb_store::LevelDB;
pub use self::memory_store::MemoryStore;
pub use self::partial_beacon_state::PartialBeaconState;
pub use errors::Error;
pub use impls::beacon_state::StorageContainer as BeaconStateStorageContainer;
pub use metrics::scrape_for_metrics;
use parking_lot::MutexGuard;
pub use types::*;

pub trait KeyValueStore<E: EthSpec>: Sync + Send + Sized + 'static {
    /// Retrieve some bytes in `column` with `key`.
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Store some `value` in `column`, indexed with `key`.
    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Same as put_bytes() but also force a flush to disk
    fn put_bytes_sync(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Flush to disk.  See
    /// https://chromium.googlesource.com/external/leveldb/+/HEAD/doc/index.md#synchronous-writes
    /// for details.
    fn sync(&self) -> Result<(), Error>;

    /// Return `true` if `key` exists in `column`.
    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error>;

    /// Removes `key` from `column`.
    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error>;

    /// Execute either all of the operations in `batch` or none at all, returning an error.
    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error>;

    /// Return a mutex guard that can be used to synchronize sensitive transactions.
    ///
    /// This doesn't prevent other threads writing to the DB unless they also use
    /// this method. In future we may implement a safer mandatory locking scheme.
    fn begin_rw_transaction(&self) -> MutexGuard<()>;

    /// Compact the database, freeing space used by deleted items.
    fn compact(&self) -> Result<(), Error>;
}

pub fn get_key_for_col(column: &str, key: &[u8]) -> Vec<u8> {
    let mut result = column.as_bytes().to_vec();
    result.extend_from_slice(key);
    result
}

pub enum KeyValueStoreOp {
    PutKeyValue(Vec<u8>, Vec<u8>),
    DeleteKey(Vec<u8>),
}

pub trait ItemStore<E: EthSpec>: KeyValueStore<E> + Sync + Send + Sized + 'static {
    /// Store an item in `Self`.
    fn put<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.put_bytes(column, key, &item.as_store_bytes())
            .map_err(Into::into)
    }

    fn put_sync<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.put_bytes_sync(column, key, &item.as_store_bytes())
            .map_err(Into::into)
    }

    /// Retrieve an item from `Self`.
    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        match self.get_bytes(column, key)? {
            Some(bytes) => Ok(Some(I::from_store_bytes(&bytes[..])?)),
            None => Ok(None),
        }
    }

    /// Returns `true` if the given key represents an item in `Self`.
    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.key_exists(column, key)
    }

    /// Remove an item from `Self`.
    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.key_delete(column, key)
    }
}

/// Reified key-value storage operation.  Helps in modifying the storage atomically.
/// See also https://github.com/sigp/lighthouse/issues/692
pub enum StoreOp<'a, E: EthSpec> {
    PutBlock(Hash256, Box<SignedBeaconBlock<E>>),
    PutState(Hash256, &'a BeaconState<E>),
    PutStateSummary(Hash256, HotStateSummary),
    PutStateTemporaryFlag(Hash256),
    DeleteStateTemporaryFlag(Hash256),
    DeleteBlock(Hash256),
    DeleteState(Hash256, Option<Slot>),
}

/// A unique column identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DBColumn {
    /// For data related to the database itself.
    BeaconMeta,
    BeaconBlock,
    BeaconState,
    /// For persisting in-memory state to the database.
    BeaconChain,
    OpPool,
    Eth1Cache,
    ForkChoice,
    PubkeyCache,
    /// For the table mapping restore point numbers to state roots.
    BeaconRestorePoint,
    /// For the mapping from state roots to their slots or summaries.
    BeaconStateSummary,
    /// For the list of temporary states stored during block import,
    /// and then made non-temporary by the deletion of their state root from this column.
    BeaconStateTemporary,
    BeaconBlockRoots,
    BeaconStateRoots,
    BeaconHistoricalRoots,
    BeaconRandaoMixes,
    DhtEnrs,
}

impl Into<&'static str> for DBColumn {
    /// Returns a `&str` prefix to be added to keys before they hit the key-value database.
    fn into(self) -> &'static str {
        match self {
            DBColumn::BeaconMeta => "bma",
            DBColumn::BeaconBlock => "blk",
            DBColumn::BeaconState => "ste",
            DBColumn::BeaconChain => "bch",
            DBColumn::OpPool => "opo",
            DBColumn::Eth1Cache => "etc",
            DBColumn::ForkChoice => "frk",
            DBColumn::PubkeyCache => "pkc",
            DBColumn::BeaconRestorePoint => "brp",
            DBColumn::BeaconStateSummary => "bss",
            DBColumn::BeaconStateTemporary => "bst",
            DBColumn::BeaconBlockRoots => "bbr",
            DBColumn::BeaconStateRoots => "bsr",
            DBColumn::BeaconHistoricalRoots => "bhr",
            DBColumn::BeaconRandaoMixes => "brm",
            DBColumn::DhtEnrs => "dht",
        }
    }
}

impl DBColumn {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn as_bytes(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }
}

/// An item that may stored in a `Store` by serializing and deserializing from bytes.
pub trait StoreItem: Sized {
    /// Identifies which column this item should be placed in.
    fn db_column() -> DBColumn;

    /// Serialize `self` as bytes.
    fn as_store_bytes(&self) -> Vec<u8>;

    /// De-serialize `self` from bytes.
    ///
    /// Return an instance of the type and the number of bytes that were read.
    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error>;

    fn as_kv_store_op(&self, key: Hash256) -> KeyValueStoreOp {
        let db_key = get_key_for_col(Self::db_column().into(), key.as_bytes());
        KeyValueStoreOp::PutKeyValue(db_key, self.as_store_bytes())
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

        fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Self::from_ssz_bytes(bytes).map_err(Into::into)
        }
    }

    fn test_impl(store: impl ItemStore<MinimalEthSpec>) {
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), true);

        let retrieved = store.get(&key).unwrap().unwrap();
        assert_eq!(item, retrieved);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        assert_eq!(store.get::<StorableThing>(&key).unwrap(), None);
    }

    #[test]
    fn simplediskdb() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let store = LevelDB::open(&path).unwrap();

        test_impl(store);
    }

    #[test]
    fn memorydb() {
        let store = MemoryStore::open();

        test_impl(store);
    }

    #[test]
    fn exists() {
        let store = MemoryStore::<MinimalEthSpec>::open();
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), true);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);
    }
}
