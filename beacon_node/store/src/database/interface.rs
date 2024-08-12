#[cfg(feature = "leveldb")]
use crate::database::leveldb_impl;
#[cfg(feature = "redb")]
use crate::database::redb_impl;
use crate::{config::DatabaseBackend, KeyValueStoreOp, StoreConfig};
use crate::{ColumnIter, ColumnKeyIter, DBColumn, Error, ItemStore, Key, KeyValueStore};
use std::path::Path;
use types::EthSpec;

pub enum BeaconNodeBackend<E: EthSpec> {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::LevelDB<E>),
    #[cfg(feature = "redb")]
    Redb(redb_impl::Redb<E>),
}

impl<E: EthSpec> ItemStore<E> for BeaconNodeBackend<E> {}

impl<E: EthSpec> KeyValueStore<E> for BeaconNodeBackend<E> {
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::get_bytes(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::get_bytes(txn, column, key),
        }
    }

    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options(),
            ),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options(),
            ),
        }
    }

    fn put_bytes_sync(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options_sync(),
            ),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options_sync(),
            ),
        }
    }

    fn sync(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::put_bytes_with_options(
                txn,
                "sync",
                b"sync",
                b"sync",
                txn.write_options_sync(),
            ),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::sync(txn),
        }
    }

    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_exists(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_exists(txn, column, key),
        }
    }

    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_delete(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_delete(txn, column, key),
        }
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::do_atomically(txn, batch),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::do_atomically(txn, batch),
        }
    }

    fn begin_rw_transaction(&self) -> parking_lot::MutexGuard<()> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::begin_rw_transaction(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::begin_rw_transaction(txn),
        }
    }

    fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }

    fn iter_column_keys_from<K: Key>(&self, _column: DBColumn, from: &[u8]) -> ColumnKeyIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_keys_from(txn, _column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => {
                redb_impl::Redb::iter_column_keys_from(txn, _column, from)
            }
        }
    }

    fn iter_column_keys<K: Key>(&self, _column: DBColumn) -> ColumnKeyIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_keys(txn, _column)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_keys(txn, _column),
        }
    }

    fn iter_column_from<K: Key>(
        &self,
        column: DBColumn,
        from: &[u8],
        predicate: impl Fn(&[u8], &[u8]) -> bool + 'static,
    ) -> ColumnIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_from(txn, column, from, predicate)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => {
                redb_impl::Redb::iter_column_from(txn, column, from, predicate)
            }
        }
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact_column(txn, _column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }
}

impl<E: EthSpec> BeaconNodeBackend<E> {
    pub fn open(config: &StoreConfig, path: &Path) -> Result<Self, Error> {
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => {
                leveldb_impl::LevelDB::open(path).map(BeaconNodeBackend::LevelDb)
            }
            #[cfg(feature = "redb")]
            DatabaseBackend::Redb => redb_impl::Redb::open(path).map(BeaconNodeBackend::Redb),
        }
    }

    pub fn put_bytes_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions,
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::put_bytes_with_options(txn, col, key, val, opts)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => {
                redb_impl::Redb::put_bytes_with_options(txn, col, key, val, opts)
            }
        }
    }

    pub fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::get_bytes(txn, col, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::get_bytes(txn, col, key),
        }
    }

    pub fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_delete(txn, col, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_delete(txn, col, key),
        }
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::do_atomically(txn, ops_batch),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::do_atomically(txn, ops_batch),
        }
    }

    pub fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }

    pub fn compact_column(&self, _column: DBColumn) -> Result<(), crate::Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact_column(txn, _column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }

    pub fn iter_column<K: Key>(&self, column: DBColumn) -> ColumnIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::iter_column(txn, column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column(txn, column),
        }
    }
}

pub struct WriteOptions {
    /// fsync before acknowledging a write operation.
    pub sync: bool,
}

impl WriteOptions {
    pub fn new() -> Self {
        WriteOptions { sync: false }
    }
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self::new()
    }
}
