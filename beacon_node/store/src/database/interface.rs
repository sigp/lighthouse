#[cfg(feature = "leveldb")]
use crate::database::leveldb_impl;
#[cfg(feature = "redb")]
use crate::database::redb_impl;
#[cfg(feature = "postgres")]
use crate::database::postgres_impl;
use crate::{config::DatabaseBackend, KeyValueStoreOp, StoreConfig};
use crate::database::async_interface::AsyncKeyValueStore;
use crate::{metrics, ColumnIter, ColumnKeyIter, DBColumn, Error, ItemStore, Key, KeyValueStore};
use std::collections::HashSet;
use std::path::Path;
use types::EthSpec;

pub enum BeaconNodeBackend<E: EthSpec> {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::LevelDB<E>),
    #[cfg(feature = "redb")]
    Redb(redb_impl::Redb<E>),
    #[cfg(feature = "postgres")]
    PostgresDB(postgres_impl::PostgresDB<E>)
}

impl<E: EthSpec> ItemStore<E> for BeaconNodeBackend<E> {}

impl<E: EthSpec> KeyValueStore<E> for BeaconNodeBackend<E> {
    fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::get_bytes(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::get_bytes(txn, column, key),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(ref txn) => {
                let rt = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
                rt.block_on(txn.get_bytes(column, key))
            }
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
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(ref db) => {
                let rt = tokio::runtime::Runtime::new().expect("Failed to block tokio runtime");
                rt.block_on(db.put_bytes(column, key, value))
            }
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
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn sync(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::sync(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::sync(txn),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_exists(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_exists(txn, column, key),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_delete(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_delete(txn, column, key),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::do_atomically(txn, batch),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::do_atomically(txn, batch),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn iter_column_keys_from<K: Key>(
        &self,
        _column: DBColumn,
        from: &[u8],
    ) -> ColumnKeyIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_keys_from(txn, _column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => {
                redb_impl::Redb::iter_column_keys_from(txn, _column, from)
            }
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::iter_column_keys(txn, column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_keys(txn, column),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_from(txn, column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_from(txn, column, from),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact_column(txn, _column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
        }
    }

    fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::delete_batch(txn, col, ops),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::delete_batch(txn, col, ops),
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
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
            #[cfg(feature = "postgres")]
            BeaconNodeBackend::PostgresDB(_) => {
                todo!("Implement PostgresDB logic");
            }
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
            #[cfg(feature = "postgres")]
            DatabaseBackend::PostgresDB => {
                use crate::{database::postgres_impl::PostgresDB};
                
                let db_url = config
                    .postgres_url
                    .as_ref()
                    .ok_or_else(|| Error::DBError {
                        message: "Missing Postgres URL".into(),
                    })?;

                // Create a Tokio runtime for sync context
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| Error::DBError {
                        message: format!("Failed to create tokio runtime: {}", e),
                    })?;
                let db = rt.block_on(PostgresDB::new(db_url))
                    .map_err(|e| Error::DBError {
                        message: format!("Failed to init PostgresDB: {:?}", e),
                    })?;

                Ok(BeaconNodeBackend::PostgresDB(db))
            }
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
