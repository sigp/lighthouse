use std::path::Path;

use leveldb::iterator::KeyIterator;
use leveldb::options::WriteOptions;
use types::EthSpec;

use crate::leveldb_store::BytesKey;
use crate::{DBColumn, ColumnIter, ItemStore, KeyValueStore, Error, ColumnKeyIter};
use crate::{StoreConfig, config::DatabaseBackend, KeyValueStoreOp};
use crate::database::leveldb_impl;

impl<E: EthSpec> ItemStore<E> for BeaconNodeBackend<E> {}

impl<E: EthSpec> KeyValueStore<E> for BeaconNodeBackend<E> {
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::get_bytes(txn, column, key),
        }
    }

    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::put_bytes_with_options(txn, column, key, value, WriteOptions::new()),
        }
    }

    fn put_bytes_sync(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::put_bytes_with_options(txn, column, key, value, WriteOptions::new()),
        }
    }

    fn sync(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::put_bytes_with_options(txn, "sync", b"sync", b"sync", WriteOptions::new()),
        }
    }

    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::key_exists(txn, column, key),
        }
    }

    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::key_delete(txn, column, key),
        }
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::do_atomically(txn, batch),
        }
    }

    fn begin_rw_transaction(&self) -> parking_lot::MutexGuard<()> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::begin_rw_transaction(txn),
        }
    }

    fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::compact(txn),
        }
    }

    fn iter_column_keys(&self, _column: DBColumn) -> ColumnKeyIter {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::iter_column_keys(txn, _column),
        }
    }
}

pub enum BeaconNodeBackend<E: EthSpec> {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::BeaconNodeBackend<E>),
}

impl<E: EthSpec> BeaconNodeBackend<E> {
    pub fn open(config: &StoreConfig, path: &Path) -> Result<Self, Error> {
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => leveldb_impl::BeaconNodeBackend::open(path).map(BeaconNodeBackend::LevelDb),
        }
    }

    pub fn put_bytes_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::put_bytes_with_options(txn, col, key, val, opts),
        }
    }

    pub fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::get_bytes(txn, col, key),
        }
    }

    pub fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> { 
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::key_delete(txn, col, key),
        }
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) =>leveldb_impl::BeaconNodeBackend::do_atomically(txn, ops_batch),
        }
    }

    pub fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::compact(txn),
        }
    }

    pub fn iter_column(&self, column: DBColumn) -> ColumnIter {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::iter_column(txn, column),
        }
    }

    pub fn keys_iter(&self) -> KeyIterator<BytesKey> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::BeaconNodeBackend::keys_iter(txn)
        }
    }
}