//! Storage functionality for Lighthouse.
//!
//! Provides the following stores:
//!
//! - `DiskStore`: an on-disk store backed by leveldb. Used in production.
//! - `MemoryStore`: an in-memory store backed by a hash-map. Used for testing.
//!
//! Provides a simple API for storing/retrieving all types that sometimes needs type-hints. See
//! tests for implementation examples.
#[macro_use]
extern crate lazy_static;

mod block_at_slot;
pub mod chunked_iter;
pub mod chunked_vector;
pub mod config;
mod errors;
mod forwards_iter;
mod hot_cold_store;
mod impls;
mod leveldb_store;
mod memory_store;
mod metrics;
mod partial_beacon_state;

pub mod iter;
pub mod migrate;

use std::sync::Arc;

pub use self::config::StoreConfig;
pub use self::hot_cold_store::HotColdDB as DiskStore;
pub use self::leveldb_store::LevelDB as SimpleDiskStore;
pub use self::memory_store::MemoryStore;
pub use self::migrate::Migrate;
pub use self::partial_beacon_state::PartialBeaconState;
pub use errors::Error;
pub use impls::beacon_state::StorageContainer as BeaconStateStorageContainer;
pub use metrics::scrape_for_metrics;
pub use types::*;

/// An object capable of storing and retrieving objects implementing `StoreItem`.
///
/// A `Store` is fundamentally backed by a key-value database, however it provides support for
/// columns. A simple column implementation might involve prefixing a key with some bytes unique to
/// each column.
pub trait Store<E: EthSpec>: Sync + Send + Sized + 'static {
    type ForwardsBlockRootsIterator: Iterator<Item = (Hash256, Slot)>;

    /// Retrieve some bytes in `column` with `key`.
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Store some `value` in `column`, indexed with `key`.
    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Return `true` if `key` exists in `column`.
    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error>;

    /// Removes `key` from `column`.
    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error>;

    /// Store an item in `Self`.
    fn put<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        item.db_put(self, key)
    }

    /// Retrieve an item from `Self`.
    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        I::db_get(self, key)
    }

    /// Returns `true` if the given key represents an item in `Self`.
    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        I::db_exists(self, key)
    }

    /// Remove an item from `Self`.
    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        I::db_delete(self, key)
    }

    /// Store a state in the store.
    fn put_state(&self, state_root: &Hash256, state: &BeaconState<E>) -> Result<(), Error>;

    /// Fetch a state from the store.
    fn get_state(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error>;

    /// Given the root of an existing block in the store (`start_block_root`), return a parent
    /// block with the specified `slot`.
    ///
    /// Returns `None` if no parent block exists at that slot, or if `slot` is greater than the
    /// slot of `start_block_root`.
    fn get_block_at_preceeding_slot(
        &self,
        start_block_root: Hash256,
        slot: Slot,
    ) -> Result<Option<(Hash256, BeaconBlock<E>)>, Error> {
        block_at_slot::get_block_at_preceeding_slot::<_, E>(self, slot, start_block_root)
    }

    /// (Optionally) Move all data before the frozen slot to the freezer database.
    fn freeze_to_state(
        _store: Arc<Self>,
        _frozen_head_root: Hash256,
        _frozen_head: &BeaconState<E>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Get a forwards (slot-ascending) iterator over the beacon block roots since `start_slot`.
    ///
    /// Will be efficient for frozen portions of the database if using `DiskStore`.
    ///
    /// The `end_state` and `end_block_root` are required for backtracking in the post-finalization
    /// part of the chain, and should be usually be set to the current head. Importantly, the
    /// `end_state` must be a state that has had a block applied to it, and the hash of that
    /// block must be `end_block_root`.
    // NOTE: could maybe optimise by getting the `BeaconState` and end block root from a closure, as
    // it's not always required.
    fn forwards_block_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Self::ForwardsBlockRootsIterator;
}

/// A unique column identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DBColumn {
    /// For data related to the database itself.
    BeaconMeta,
    BeaconBlock,
    BeaconState,
    BeaconChain,
    /// For the table mapping restore point numbers to state roots.
    BeaconRestorePoint,
    /// For the mapping from state roots to their slots.
    BeaconStateSlot,
    BeaconBlockRoots,
    BeaconStateRoots,
    BeaconHistoricalRoots,
    BeaconRandaoMixes,
}

impl Into<&'static str> for DBColumn {
    /// Returns a `&str` that can be used for keying a key-value data base.
    fn into(self) -> &'static str {
        match self {
            DBColumn::BeaconMeta => "bma",
            DBColumn::BeaconBlock => "blk",
            DBColumn::BeaconState => "ste",
            DBColumn::BeaconChain => "bch",
            DBColumn::BeaconRestorePoint => "brp",
            DBColumn::BeaconStateSlot => "bss",
            DBColumn::BeaconBlockRoots => "bbr",
            DBColumn::BeaconStateRoots => "bsr",
            DBColumn::BeaconHistoricalRoots => "bhr",
            DBColumn::BeaconRandaoMixes => "brm",
        }
    }
}

/// An item that may stored in a `Store` by serializing and deserializing from bytes.
pub trait SimpleStoreItem: Sized {
    /// Identifies which column this item should be placed in.
    fn db_column() -> DBColumn;

    /// Serialize `self` as bytes.
    fn as_store_bytes(&self) -> Vec<u8>;

    /// De-serialize `self` from bytes.
    ///
    /// Return an instance of the type and the number of bytes that were read.
    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

/// An item that may be stored in a `Store`.
pub trait StoreItem: Sized {
    /// Store `self`.
    fn db_put<S: Store<E>, E: EthSpec>(&self, store: &S, key: &Hash256) -> Result<(), Error>;

    /// Retrieve an instance of `Self` from `store`.
    fn db_get<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<Option<Self>, Error>;

    /// Return `true` if an instance of `Self` exists in `store`.
    fn db_exists<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<bool, Error>;

    /// Delete an instance of `Self` from `store`.
    fn db_delete<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<(), Error>;
}

impl<T> StoreItem for T
where
    T: SimpleStoreItem,
{
    /// Store `self`.
    fn db_put<S: Store<E>, E: EthSpec>(&self, store: &S, key: &Hash256) -> Result<(), Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store
            .put_bytes(column, key, &self.as_store_bytes())
            .map_err(Into::into)
    }

    /// Retrieve an instance of `Self`.
    fn db_get<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<Option<Self>, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        match store.get_bytes(column, key)? {
            Some(bytes) => Ok(Some(Self::from_store_bytes(&bytes[..])?)),
            None => Ok(None),
        }
    }

    /// Return `true` if an instance of `Self` exists in `Store`.
    fn db_exists<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<bool, Error> {
        let column = Self::db_column().into();
        let key = key.as_bytes();

        store.key_exists(column, key)
    }

    /// Delete `self` from the `Store`.
    fn db_delete<S: Store<E>, E: EthSpec>(store: &S, key: &Hash256) -> Result<(), Error> {
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

    impl SimpleStoreItem for StorableThing {
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

    fn test_impl(store: impl Store<MinimalEthSpec>) {
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key), Ok(false));

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key), Ok(true));

        let retrieved = store.get(&key).unwrap().unwrap();
        assert_eq!(item, retrieved);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key), Ok(false));

        assert_eq!(store.get::<StorableThing>(&key), Ok(None));
    }

    #[test]
    fn diskdb() {
        use sloggers::{null::NullLoggerBuilder, Build};

        let hot_dir = tempdir().unwrap();
        let cold_dir = tempdir().unwrap();
        let slots_per_restore_point = MinimalEthSpec::slots_per_historical_root() as u64;
        let spec = MinimalEthSpec::default_spec();
        let log = NullLoggerBuilder.build().unwrap();
        let store = DiskStore::open(
            &hot_dir.path(),
            &cold_dir.path(),
            slots_per_restore_point,
            spec,
            log,
        )
        .unwrap();

        test_impl(store);
    }

    #[test]
    fn simplediskdb() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let store = SimpleDiskStore::open(&path).unwrap();

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
