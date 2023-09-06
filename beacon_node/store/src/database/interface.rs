use std::path::Path;

use leveldb::options::WriteOptions;

use crate::DBColumn;
use crate::{StoreConfig, config::DatabaseBackend, KeyValueStoreOp};
use crate::database::leveldb_impl;

pub enum Environment {
    #[cfg(feature = "leveldb")]
    LevelDb(),
}

pub enum Database {
   

}

pub enum RwTransaction {
    #[cfg(feature = "leveldb")]
    LevelDb(),
}

pub enum Options {

}

impl Environment {
    pub fn open(config: &StoreConfig, path: &Path) {
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => leveldb_impl::Environment::open(path),
        }
    }

    pub fn create_database(&self) {
        match self {
            #[cfg(feature = "leveldb")]
            Environment::LevelDb() => todo!(),
        }
    }

    pub fn create_rw_transaction(&self) {
        match self {
            #[cfg(feature = "leveldb")]
            Environment::LevelDb() => todo!(),
        }
    }
}

impl RwTransaction {
    pub fn put_with_options(
        &self,
        col: &str,
        key: &[u8],
        val: &[u8],
        opts: WriteOptions
    ) {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() => leveldb_impl::Environment::put_with_options(col, key, val, opts),
        }
    }

    pub fn get_bytes(&self, col: &str, key: &[u8]) {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() => leveldb_impl::RwTransaction::get_bytes(col, key),
        }
    }

    pub fn key_delete(&self, col: &str, key: &[u8]) { 
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() => leveldb_impl::RwTransaction::key_delete(col, key),
        }
    }

    pub fn do_atomically(&self, ops_batch: Vec<KeyValueStoreOp>) {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() =>leveldb_impl::RwTransaction::do_atomically(ops_batch),
        }
    }

    pub fn compact(&self) {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() => leveldb_impl::RwTransaction::compact(),
        }
    }

    pub fn iter_column(&self, column: DBColumn) {
        match self {
            #[cfg(feature = "leveldb")]
            RwTransaction::LevelDb() => leveldb_impl::RwTransaction::iter_column(column),
        }
    }
}