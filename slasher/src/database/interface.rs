use crate::database::mdbx_impl;
use crate::{Config, Error};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DatabaseBackend {
    Mdbx,
}

#[derive(Debug)]
pub enum Environment {
    Mdbx(mdbx_impl::Environment),
}

#[derive(Debug)]
pub enum RwTransaction<'env> {
    Mdbx(mdbx_impl::RwTransaction<'env>),
}

#[derive(Debug)]
pub enum Database<'env> {
    Mdbx(mdbx_impl::Database<'env>),
}

#[derive(Debug)]
pub enum Cursor<'env> {
    Mdbx(mdbx_impl::Cursor<'env>),
}

impl Environment {
    pub fn new(max_dbs: usize, config: &Config) -> Result<Environment, Error> {
        match config.backend {
            DatabaseBackend::Mdbx => {
                mdbx_impl::Environment::new(max_dbs, config).map(Environment::Mdbx)
            }
        }
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        match self {
            Self::Mdbx(env) => env.begin_rw_txn().map(RwTransaction::Mdbx),
        }
    }
}

impl<'env> RwTransaction<'env> {
    pub fn create_db(&self, name: &'static str) -> Result<(), Error> {
        match self {
            Self::Mdbx(txn) => txn.create_db(name),
        }
    }

    pub fn open_db(&self, name: &'static str) -> Result<Database, Error> {
        match self {
            Self::Mdbx(txn) => txn.open_db(name).map(Database::Mdbx),
        }
    }

    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.get(db, key),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.put(db, key, value),
        }
    }

    pub fn del<K: AsRef<[u8]>>(&self, db: &Database, key: K) -> Result<(), Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.del(db, key),
        }
    }

    pub fn cursor(&self, db: &Database<'env>) -> Result<Cursor<'env>, Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.cursor(db).map(Cursor::Mdbx),
        }
    }

    pub fn commit(self) -> Result<(), Error> {
        match self {
            Self::Mdbx(txn) => txn.commit(),
        }
    }
}

impl<'env> Cursor<'env> {
    /// Return the first key in the current database while advancing the cursor's position.
    pub fn first_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.first_key(),
        }
    }

    /// Return the last key in the current database while advancing the cursor's position.
    pub fn last_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.last_key(),
        }
    }

    pub fn next_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.next_key(),
        }
    }

    /// Get the key value pair at the current position.
    pub fn get_current(&mut self) -> Result<Option<(Cow<'env, [u8]>, Cow<'env, [u8]>)>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.get_current(),
        }
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.delete_current(),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        match self {
            Self::Mdbx(cursor) => cursor.put(key, value),
        }
    }
}
