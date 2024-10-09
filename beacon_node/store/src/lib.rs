//! Storage functionality for Lighthouse.
//!
//! Provides the following stores:
//!
//! - `HotColdDB`: an on-disk store backed by leveldb. Used in production.
//! - `MemoryStore`: an in-memory store backed by a hash-map. Used for testing.
//!
//! Provides a simple API for storing/retrieving all types that sometimes needs type-hints. See
//! tests for implementation examples.
pub mod chunked_iter;
pub mod chunked_vector;
pub mod config;
pub mod consensus_context;
pub mod errors;
mod forwards_iter;
mod garbage_collection;
pub mod hdiff;
pub mod historic_state_cache;
pub mod hot_cold_store;
mod impls;
mod leveldb_store;
mod memory_store;
pub mod metadata;
pub mod metrics;
pub mod partial_beacon_state;
pub mod reconstruct;
pub mod state_cache;

pub mod iter;

pub use self::config::StoreConfig;
pub use self::consensus_context::OnDiskConsensusContext;
pub use self::hot_cold_store::{HotColdDB, HotStateSummary, Split};
pub use self::leveldb_store::LevelDB;
pub use self::memory_store::MemoryStore;
pub use crate::metadata::BlobInfo;
pub use errors::Error;
pub use impls::beacon_state::StorageContainer as BeaconStateStorageContainer;
pub use metadata::AnchorInfo;
pub use metrics::scrape_for_metrics;
use parking_lot::MutexGuard;
use std::sync::Arc;
use strum::{EnumString, IntoStaticStr};
pub use types::*;

const DATA_COLUMN_DB_KEY_SIZE: usize = 32 + 8;

pub type ColumnIter<'a, K> = Box<dyn Iterator<Item = Result<(K, Vec<u8>), Error>> + 'a>;
pub type ColumnKeyIter<'a, K> = Box<dyn Iterator<Item = Result<K, Error>> + 'a>;

pub type RawEntryIter<'a> = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), Error>> + 'a>;
pub type RawKeyIter<'a> = Box<dyn Iterator<Item = Result<Vec<u8>, Error>> + 'a>;

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

    /// Compact a single column in the database, freeing space used by deleted items.
    fn compact_column(&self, column: DBColumn) -> Result<(), Error>;

    /// Compact a default set of columns that are likely to free substantial space.
    fn compact(&self) -> Result<(), Error> {
        // Compact state and block related columns as they are likely to have the most churn,
        // i.e. entries being created and deleted.
        for column in [
            DBColumn::BeaconState,
            DBColumn::BeaconStateSummary,
            DBColumn::BeaconBlock,
        ] {
            self.compact_column(column)?;
        }
        Ok(())
    }

    /// Iterate through all keys and values in a particular column.
    fn iter_column<K: Key>(&self, column: DBColumn) -> ColumnIter<K> {
        self.iter_column_from(column, &vec![0; column.key_size()])
    }

    /// Iterate through all keys and values in a column from a given starting point.
    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<K>;

    fn iter_raw_entries(&self, _column: DBColumn, _prefix: &[u8]) -> RawEntryIter {
        Box::new(std::iter::empty())
    }

    fn iter_raw_keys(&self, column: DBColumn, prefix: &[u8]) -> RawKeyIter;

    /// Iterate through all keys in a particular column.
    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<K>;
}

pub trait Key: Sized + 'static {
    fn from_bytes(key: &[u8]) -> Result<Self, Error>;
}

impl Key for Hash256 {
    fn from_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() == 32 {
            Ok(Hash256::from_slice(key))
        } else {
            Err(Error::InvalidKey)
        }
    }
}

impl Key for Vec<u8> {
    fn from_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(key.to_vec())
    }
}

pub fn get_key_for_col(column: &str, key: &[u8]) -> Vec<u8> {
    let mut result = column.as_bytes().to_vec();
    result.extend_from_slice(key);
    result
}

pub fn get_col_from_key(key: &[u8]) -> Option<String> {
    if key.len() < 3 {
        return None;
    }
    String::from_utf8(key[0..3].to_vec()).ok()
}

pub fn get_data_column_key(block_root: &Hash256, column_index: &ColumnIndex) -> Vec<u8> {
    let mut result = block_root.as_slice().to_vec();
    result.extend_from_slice(&column_index.to_le_bytes());
    result
}

pub fn parse_data_column_key(data: Vec<u8>) -> Result<(Hash256, ColumnIndex), Error> {
    if data.len() != DBColumn::BeaconDataColumn.key_size() {
        return Err(Error::InvalidKey);
    }
    // split_at panics if 32 < 40 which will never happen after the length check above
    let (block_root_bytes, column_index_bytes) = data.split_at(32);
    let block_root = Hash256::from_slice(block_root_bytes);
    // column_index_bytes is asserted to be 8 bytes after the length check above
    let column_index = ColumnIndex::from_le_bytes(
        column_index_bytes
            .try_into()
            .map_err(|_| Error::InvalidKey)?,
    );
    Ok((block_root, column_index))
}

#[must_use]
#[derive(Clone)]
pub enum KeyValueStoreOp {
    PutKeyValue(Vec<u8>, Vec<u8>),
    DeleteKey(Vec<u8>),
}

pub trait ItemStore<E: EthSpec>: KeyValueStore<E> + Sync + Send + Sized + 'static {
    /// Store an item in `Self`.
    fn put<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_slice();

        self.put_bytes(column, key, &item.as_store_bytes())
            .map_err(Into::into)
    }

    fn put_sync<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_slice();

        self.put_bytes_sync(column, key, &item.as_store_bytes())
            .map_err(Into::into)
    }

    /// Retrieve an item from `Self`.
    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        let column = I::db_column().into();
        let key = key.as_slice();

        match self.get_bytes(column, key)? {
            Some(bytes) => Ok(Some(I::from_store_bytes(&bytes[..])?)),
            None => Ok(None),
        }
    }

    /// Returns `true` if the given key represents an item in `Self`.
    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        let column = I::db_column().into();
        let key = key.as_slice();

        self.key_exists(column, key)
    }

    /// Remove an item from `Self`.
    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_slice();

        self.key_delete(column, key)
    }
}

/// Reified key-value storage operation.  Helps in modifying the storage atomically.
/// See also https://github.com/sigp/lighthouse/issues/692
#[derive(Clone)]
pub enum StoreOp<'a, E: EthSpec> {
    PutBlock(Hash256, Arc<SignedBeaconBlock<E>>),
    PutState(Hash256, &'a BeaconState<E>),
    PutBlobs(Hash256, BlobSidecarList<E>),
    PutDataColumns(Hash256, DataColumnSidecarList<E>),
    PutStateSummary(Hash256, HotStateSummary),
    PutStateTemporaryFlag(Hash256),
    DeleteStateTemporaryFlag(Hash256),
    DeleteBlock(Hash256),
    DeleteBlobs(Hash256),
    DeleteDataColumns(Hash256, Vec<ColumnIndex>),
    DeleteState(Hash256, Option<Slot>),
    DeleteExecutionPayload(Hash256),
    DeleteSyncCommitteeBranch(Hash256),
    KeyValueOp(KeyValueStoreOp),
}

/// A unique column identifier.
#[derive(Debug, Clone, Copy, PartialEq, IntoStaticStr, EnumString)]
pub enum DBColumn {
    /// For data related to the database itself.
    #[strum(serialize = "bma")]
    BeaconMeta,
    /// Data related to blocks.
    ///
    /// - Key: `Hash256` block root.
    /// - Value in hot DB: SSZ-encoded blinded block.
    /// - Value in cold DB: 8-byte slot of block.
    #[strum(serialize = "blk")]
    BeaconBlock,
    #[strum(serialize = "blb")]
    BeaconBlob,
    #[strum(serialize = "bdc")]
    BeaconDataColumn,
    /// For full `BeaconState`s in the hot database (finalized or fork-boundary states).
    #[strum(serialize = "ste")]
    BeaconState,
    /// For beacon state snapshots in the freezer DB.
    #[strum(serialize = "bsn")]
    BeaconStateSnapshot,
    /// For compact `BeaconStateDiff`s in the freezer DB.
    #[strum(serialize = "bsd")]
    BeaconStateDiff,
    /// Mapping from state root to `HotStateSummary` in the hot DB.
    ///
    /// Previously this column also served a role in the freezer DB, mapping state roots to
    /// `ColdStateSummary`. However that role is now filled by `BeaconColdStateSummary`.
    #[strum(serialize = "bss")]
    BeaconStateSummary,
    /// Mapping from state root to `ColdStateSummary` in the cold DB.
    #[strum(serialize = "bcs")]
    BeaconColdStateSummary,
    /// For the list of temporary states stored during block import,
    /// and then made non-temporary by the deletion of their state root from this column.
    #[strum(serialize = "bst")]
    BeaconStateTemporary,
    /// Execution payloads for blocks more recent than the finalized checkpoint.
    #[strum(serialize = "exp")]
    ExecPayload,
    /// For persisting in-memory state to the database.
    #[strum(serialize = "bch")]
    BeaconChain,
    #[strum(serialize = "opo")]
    OpPool,
    #[strum(serialize = "etc")]
    Eth1Cache,
    #[strum(serialize = "frk")]
    ForkChoice,
    #[strum(serialize = "pkc")]
    PubkeyCache,
    /// For the legacy table mapping restore point numbers to state roots.
    ///
    /// DEPRECATED. Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "brp")]
    BeaconRestorePoint,
    /// Mapping from slot to beacon state root in the freezer DB.
    ///
    /// This new column was created to replace the previous `bsr` column. The replacement was
    /// necessary to guarantee atomicity of the upgrade migration.
    #[strum(serialize = "bsx")]
    BeaconStateRoots,
    /// DEPRECATED. This is the previous column for beacon state roots stored by "chunk index".
    ///
    /// Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "bsr")]
    BeaconStateRootsChunked,
    /// Mapping from slot to beacon block root in the freezer DB.
    ///
    /// This new column was created to replace the previous `bbr` column. The replacement was
    /// necessary to guarantee atomicity of the upgrade migration.
    #[strum(serialize = "bbx")]
    BeaconBlockRoots,
    /// DEPRECATED. This is the previous column for beacon block roots stored by "chunk index".
    ///
    /// Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "bbr")]
    BeaconBlockRootsChunked,
    /// DEPRECATED. Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "bhr")]
    BeaconHistoricalRoots,
    /// DEPRECATED. Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "brm")]
    BeaconRandaoMixes,
    #[strum(serialize = "dht")]
    DhtEnrs,
    /// For Optimistically Imported Merge Transition Blocks
    #[strum(serialize = "otb")]
    OptimisticTransitionBlock,
    /// DEPRECATED. Can be removed once schema v22 is buried by a hard fork.
    #[strum(serialize = "bhs")]
    BeaconHistoricalSummaries,
    #[strum(serialize = "olc")]
    OverflowLRUCache,
    /// For persisting eagerly computed light client data
    #[strum(serialize = "lcu")]
    LightClientUpdate,
    /// For helping persist eagerly computed light client bootstrap data
    #[strum(serialize = "scb")]
    SyncCommitteeBranch,
    /// For helping persist eagerly computed light client bootstrap data
    #[strum(serialize = "scm")]
    SyncCommittee,
}

/// A block from the database, which might have an execution payload or not.
pub enum DatabaseBlock<E: EthSpec> {
    Full(SignedBeaconBlock<E>),
    Blinded(SignedBeaconBlock<E, BlindedPayload<E>>),
}

impl DBColumn {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn as_bytes(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }

    /// Most database keys are 32 bytes, but some freezer DB keys are 8 bytes.
    ///
    /// This function returns the number of bytes used by keys in a given column.
    pub fn key_size(self) -> usize {
        match self {
            Self::OverflowLRUCache => 33, // DEPRECATED
            Self::BeaconMeta
            | Self::BeaconBlock
            | Self::BeaconState
            | Self::BeaconBlob
            | Self::BeaconStateSummary
            | Self::BeaconColdStateSummary
            | Self::BeaconStateTemporary
            | Self::ExecPayload
            | Self::BeaconChain
            | Self::OpPool
            | Self::Eth1Cache
            | Self::ForkChoice
            | Self::PubkeyCache
            | Self::BeaconRestorePoint
            | Self::DhtEnrs
            | Self::OptimisticTransitionBlock => 32,
            Self::BeaconBlockRoots
            | Self::BeaconBlockRootsChunked
            | Self::BeaconStateRoots
            | Self::BeaconStateRootsChunked
            | Self::BeaconHistoricalRoots
            | Self::BeaconHistoricalSummaries
            | Self::BeaconRandaoMixes
            | Self::BeaconStateSnapshot
            | Self::BeaconStateDiff
            | Self::SyncCommittee
            | Self::SyncCommitteeBranch
            | Self::LightClientUpdate => 8,
            Self::BeaconDataColumn => DATA_COLUMN_DB_KEY_SIZE,
        }
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
        let db_key = get_key_for_col(Self::db_column().into(), key.as_slice());
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

        assert!(!store.exists::<StorableThing>(&key).unwrap());

        store.put(&key, &item).unwrap();

        assert!(store.exists::<StorableThing>(&key).unwrap());

        let retrieved = store.get(&key).unwrap().unwrap();
        assert_eq!(item, retrieved);

        store.delete::<StorableThing>(&key).unwrap();

        assert!(!store.exists::<StorableThing>(&key).unwrap());

        assert_eq!(store.get::<StorableThing>(&key).unwrap(), None);
    }

    #[test]
    fn simplediskdb() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let store = LevelDB::open(path).unwrap();

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

        assert!(!store.exists::<StorableThing>(&key).unwrap());

        store.put(&key, &item).unwrap();

        assert!(store.exists::<StorableThing>(&key).unwrap());

        store.delete::<StorableThing>(&key).unwrap();

        assert!(!store.exists::<StorableThing>(&key).unwrap());
    }

    #[test]
    fn test_get_col_from_key() {
        let key = get_key_for_col(DBColumn::BeaconBlock.into(), &[1u8; 32]);
        let col = get_col_from_key(&key).unwrap();
        assert_eq!(col, "blk");
    }
}
