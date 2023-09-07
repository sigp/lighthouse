use std::path::Path;

use leveldb::options::WriteOptions;
use types::EthSpec;

use crate::{DBColumn, ColumnIter};
use crate::{StoreConfig, config::DatabaseBackend, KeyValueStoreOp};
use crate::database::leveldb_impl;

use super::leveldb_impl::Error;

pub enum Environment {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::Environment),
}

pub enum Database {
   

}

pub enum RwTransaction {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::RwTransaction),
}

pub enum Options {

}

impl Environment {
    pub fn open(config: &StoreConfig, path: &Path) -> Result<Self, Error> {
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => leveldb_impl::Environment::open(path).map(Environment::LevelDb),
        }
    }
}

impl RwTransaction {
    pub fn put_bytes_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) => leveldb_impl::RwTransaction::put_bytes_with_options(txn, col, key, val, opts),
        }
    }

    pub fn get_bytes(&self, col: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) => leveldb_impl::RwTransaction::get_bytes(txn, col, key),
        }
    }

    pub fn key_delete(&self, col: &str, key: &[u8]) -> Result<(), Error> { 
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) => leveldb_impl::RwTransaction::key_delete(txn, col, key),
        }
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) =>leveldb_impl::RwTransaction::do_atomically(txn, ops_batch),
        }
    }

    pub fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) => leveldb_impl::RwTransaction::compact(txn),
        }
    }

    pub fn iter_column(&self, column: DBColumn) -> ColumnIter {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb(txn) => leveldb_impl::RwTransaction::iter_column(txn, column),
        }
    }
}