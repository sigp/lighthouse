use crate::database::{lmdb_impl, mdbx_impl};
use crate::{Config, DatabaseBackend, Error};
use std::borrow::Cow;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Environment {
    Mdbx(mdbx_impl::Environment),
    Lmdb(lmdb_impl::Environment),
}

#[derive(Debug)]
pub enum RwTransaction<'env> {
    Mdbx(mdbx_impl::RwTransaction<'env>),
    Lmdb(lmdb_impl::RwTransaction<'env>),
}

#[derive(Debug)]
pub enum Database<'env> {
    Mdbx(mdbx_impl::Database<'env>),
    Lmdb(lmdb_impl::Database<'env>),
}

#[derive(Debug)]
pub struct OpenDatabases<'env> {
    pub indexed_attestation_db: Database<'env>,
    pub indexed_attestation_id_db: Database<'env>,
    pub attesters_db: Database<'env>,
    pub attesters_max_targets_db: Database<'env>,
    pub min_targets_db: Database<'env>,
    pub max_targets_db: Database<'env>,
    pub current_epochs_db: Database<'env>,
    pub proposers_db: Database<'env>,
    pub metadata_db: Database<'env>,
}

#[derive(Debug)]
pub enum Cursor<'env> {
    Mdbx(mdbx_impl::Cursor<'env>),
    Lmdb(lmdb_impl::Cursor<'env>),
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        match config.backend {
            DatabaseBackend::Mdbx => mdbx_impl::Environment::new(config).map(Environment::Mdbx),
            DatabaseBackend::Lmdb => lmdb_impl::Environment::new(config).map(Environment::Lmdb),
        }
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        match self {
            Self::Mdbx(env) => env.create_databases(),
            Self::Lmdb(env) => env.create_databases(),
        }
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        match self {
            Self::Mdbx(env) => env.begin_rw_txn().map(RwTransaction::Mdbx),
            Self::Lmdb(env) => env.begin_rw_txn().map(RwTransaction::Lmdb),
        }
    }

    /// List of all files used by the database.
    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        match self {
            Self::Mdbx(env) => env.filenames(config),
            Self::Lmdb(env) => env.filenames(config),
        }
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.get(db, key),
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.get(db, key),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.put(db, key, value),
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.put(db, key, value),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.del(db, key),
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.del(db, key),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn cursor<'a>(&'a mut self, db: &Database) -> Result<Cursor<'a>, Error> {
        match (self, db) {
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.cursor(db).map(Cursor::Mdbx),
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.cursor(db).map(Cursor::Lmdb),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn commit(self) -> Result<(), Error> {
        match self {
            Self::Mdbx(txn) => txn.commit(),
            Self::Lmdb(txn) => txn.commit(),
        }
    }
}

impl<'env> Cursor<'env> {
    /// Return the first key in the current database while advancing the cursor's position.
    pub fn first_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.first_key(),
            Cursor::Lmdb(cursor) => cursor.first_key(),
        }
    }

    /// Return the last key in the current database while advancing the cursor's position.
    pub fn last_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.last_key(),
            Cursor::Lmdb(cursor) => cursor.last_key(),
        }
    }

    pub fn next_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.next_key(),
            Cursor::Lmdb(cursor) => cursor.next_key(),
        }
    }

    /// Get the key value pair at the current position.
    pub fn get_current(&mut self) -> Result<Option<(Cow<'env, [u8]>, Cow<'env, [u8]>)>, Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.get_current(),
            Cursor::Lmdb(cursor) => cursor.get_current(),
        }
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        match self {
            Cursor::Mdbx(cursor) => cursor.delete_current(),
            Cursor::Lmdb(cursor) => cursor.delete_current(),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        match self {
            Self::Mdbx(cursor) => cursor.put(key, value),
            Self::Lmdb(cursor) => cursor.put(key, value),
        }
    }
}
