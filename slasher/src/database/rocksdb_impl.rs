#![cfg(feature = "rocksdb")]

use crate::{
    config::MEGABYTE,
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};
use lmdb::{Cursor as _, DatabaseFlags, Transaction, WriteFlags};
use lmdb_sys::{MDB_FIRST, MDB_GET_CURRENT, MDB_LAST, MDB_NEXT};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Environment {
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
}

#[derive(Debug)]
pub struct Database<'env> {
}

#[derive(Debug)]
pub struct Cursor<'env> {
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        todo!();
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        todo!();
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        todo!();
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        todo!();
    }

    fn db_flags() -> DatabaseFlags {
        todo!();
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        todo!();
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        todo!();
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        todo!();
    }

    pub fn cursor<'a>(&'a mut self, db: &Database) -> Result<Cursor<'a>, Error> {
        todo!();
    }

    pub fn commit(self) -> Result<(), Error> {
        todo!();
    }

    fn write_flags() -> WriteFlags {
        todo!();
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        todo!();
    }

    pub fn last_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        todo!();
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        todo!();
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        todo!();
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        todo!();
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        todo!();
    }
}

/// Mix-in trait for loading values from LMDB that may or may not exist.
pub trait TxnOptional<T, E> {
    fn optional(self) -> Result<Option<T>, E>;
}

impl<T> TxnOptional<T, Error> for Result<T, ()> {
    fn optional(self) -> Result<Option<T>, ()> {
        todo!();
    }
}
