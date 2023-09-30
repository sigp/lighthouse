use crate::{Config, DatabaseBackend, Error};
use std::borrow::Cow;
use std::marker::PhantomData;
use std::path::PathBuf;

#[cfg(feature = "lmdb")]
use crate::database::lmdb_impl;
#[cfg(feature = "mdbx")]
use crate::database::mdbx_impl;
#[cfg(feature = "sqlite")]
use crate::database::sqlite_impl;

#[derive(Debug)]
pub enum Environment {
    #[cfg(feature = "mdbx")]
    Mdbx(mdbx_impl::Environment),
    #[cfg(feature = "lmdb")]
    Lmdb(lmdb_impl::Environment),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlite_impl::Environment),
    Disabled,
}

#[derive(Debug)]
pub enum RwTransaction<'env> {
    #[cfg(feature = "mdbx")]
    Mdbx(mdbx_impl::RwTransaction<'env>),
    #[cfg(feature = "lmdb")]
    Lmdb(lmdb_impl::RwTransaction<'env>),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlite_impl::RwTransaction<'env>),
    Disabled(PhantomData<&'env ()>),
}

#[derive(Debug)]
pub enum Database<'env> {
    #[cfg(feature = "mdbx")]
    Mdbx(mdbx_impl::Database<'env>),
    #[cfg(feature = "lmdb")]
    Lmdb(lmdb_impl::Database<'env>),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlite_impl::Database<'env>),
    Disabled(PhantomData<&'env ()>),
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

pub type Key<'a> = Cow<'a, [u8]>;
pub type Value<'a> = Cow<'a, [u8]>;

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        match config.backend {
            #[cfg(feature = "mdbx")]
            DatabaseBackend::Mdbx => mdbx_impl::Environment::new(config).map(Environment::Mdbx),
            #[cfg(feature = "lmdb")]
            DatabaseBackend::Lmdb => lmdb_impl::Environment::new(config).map(Environment::Lmdb),
            #[cfg(feature = "sqlite")]
            DatabaseBackend::Sqlite => {
                sqlite_impl::Environment::new(config).map(Environment::Sqlite)
            }
            DatabaseBackend::Disabled => Err(Error::SlasherDatabaseBackendDisabled),
        }
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        match self {
            #[cfg(feature = "mdbx")]
            Self::Mdbx(env) => env.create_databases(),
            #[cfg(feature = "lmdb")]
            Self::Lmdb(env) => env.create_databases(),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(env) => env.create_databases(),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        match self {
            /* */
            #[cfg(feature = "mdbx")]
            Self::Mdbx(env) => env.begin_rw_txn().map(RwTransaction::Mdbx),
            #[cfg(feature = "lmdb")]
            Self::Lmdb(env) => env.begin_rw_txn().map(RwTransaction::Lmdb),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(env) => env.begin_rw_txn().map(RwTransaction::Sqlite),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    /// List of all files used by the database.
    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        match self {
            #[cfg(feature = "mdbx")]
            Self::Mdbx(env) => env.filenames(config),
            #[cfg(feature = "lmdb")]
            Self::Lmdb(env) => env.filenames(config),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(env) => env.filenames(config),
            _ => vec![],
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
            #[cfg(feature = "mdbx")]
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.get(db, key),
            #[cfg(feature = "lmdb")]
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.get(db, key),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.get(db, key),
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
            #[cfg(feature = "mdbx")]
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.put(db, key, value),
            #[cfg(feature = "lmdb")]
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.put(db, key, value),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.put(db, key, value),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.del(db, key),
            #[cfg(feature = "lmdb")]
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.del(db, key),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.del(db, key),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn first_key(&mut self, db: &Database) -> Result<Option<Key>, Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            Cursor::Mdbx(cursor) => cursor.first_key(),
            #[cfg(feature = "lmdb")]
            Cursor::Lmdb(cursor) => cursor.first_key(),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.first_key(db),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    /// Return the last key in the current database while advancing the cursor's position.
    pub fn last_key(&mut self, db: &Database) -> Result<Option<Key>, Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            Cursor::Mdbx(cursor) => cursor.last_key(),
            #[cfg(feature = "lmdb")]
            Cursor::Lmdb(cursor) => cursor.last_key(),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.last_key(db),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn next_key(&mut self, db: &Database) -> Result<Option<Key>, Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            Cursor::Mdbx(cursor) => cursor.next_key(),
            #[cfg(feature = "lmdb")]
            Cursor::Lmdb(cursor) => cursor.next_key(),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.next_key(db),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    /// Get the key value pair at the current position.
    pub fn get_current(&mut self, db: &Database) -> Result<Option<(Key, Value)>, Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            Cursor::Mdbx(cursor) => cursor.get_current(),
            #[cfg(feature = "lmdb")]
            Cursor::Lmdb(cursor) => cursor.get_current(),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.get_current(db),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn delete_current(&mut self, db: &Database) -> Result<(), Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            Cursor::Mdbx(cursor) => cursor.delete_current(),
            #[cfg(feature = "lmdb")]
            Cursor::Lmdb(cursor) => cursor.delete_current(),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.delete_current(db),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn delete_while(
        &mut self,
        db: &Database,
        f: impl Fn(&[u8]) -> Result<bool, Error>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        match (self, db) {
            #[cfg(feature = "mdbx")]
            (Self::Mdbx(txn), Database::Mdbx(db)) => txn.del(db, key),
            #[cfg(feature = "lmdb")]
            (Self::Lmdb(txn), Database::Lmdb(db)) => txn.del(db, key),
            #[cfg(feature = "sqlite")]
            (Self::Sqlite(txn), Database::Sqlite(db)) => txn.delete_while(db, f),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }

    pub fn commit(self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "mdbx")]
            Self::Mdbx(txn) => txn.commit(),
            #[cfg(feature = "lmdb")]
            Self::Lmdb(txn) => txn.commit(),
            #[cfg(feature = "sqlite")]
            Self::Sqlite(txn) => txn.commit(),
            _ => Err(Error::MismatchedDatabaseVariant),
        }
    }
}
