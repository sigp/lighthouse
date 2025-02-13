#[cfg(feature = "leveldb")]
use crate::database::leveldb_impl;
#[cfg(feature = "redb")]
use crate::database::redb_impl;
use crate::{config::DatabaseBackend, KeyValueStoreOp, StoreConfig};
use crate::{metrics, ColumnIter, ColumnKeyIter, DBColumn, Error, ItemStore, Key, KeyValueStore};
use std::collections::HashSet;
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
    fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::get_bytes(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::get_bytes(txn, column, key),
        }
    }

    fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
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

    fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
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
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::sync(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::sync(txn),
        }
    }

    fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_exists(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_exists(txn, column, key),
        }
    }

    fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
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

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::iter_column_keys(txn, column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_keys(txn, column),
        }
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_from(txn, column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_from(txn, column, from),
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

    fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::delete_batch(txn, col, ops),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::delete_batch(txn, col, ops),
        }
    }

    fn delete_if(
        &self,
        column: DBColumn,
        f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::delete_if(txn, column, f),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::delete_if(txn, column, f),
        }
    }
}

impl<E: EthSpec> BeaconNodeBackend<E> {
    pub fn open(config: &StoreConfig, path: &Path) -> Result<Self, Error> {
        metrics::inc_counter_vec(&metrics::DISK_DB_TYPE, &[&config.backend.to_string()]);
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => {
                leveldb_impl::LevelDB::open(path).map(BeaconNodeBackend::LevelDb)
            }
            #[cfg(feature = "redb")]
            DatabaseBackend::Redb => redb_impl::Redb::open(path).map(BeaconNodeBackend::Redb),
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
