#![cfg(feature = "lmdb")]

use crate::{
    config::MEGABYTE,
    database::{
        interface::{Key, Value},
        *,
    },
};
use lmdb::{Cursor as _, DatabaseFlags, Transaction, WriteFlags};
use lmdb_sys::{MDB_FIRST, MDB_GET_CURRENT, MDB_LAST, MDB_NEXT};
use std::path::PathBuf;

#[derive(Debug)]
pub struct Environment {
    env: lmdb::Environment,
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    txn: lmdb::RwTransaction<'env>,
}

#[derive(Debug)]
pub struct Database<'env> {
    db: lmdb::Database,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Debug)]
pub struct Cursor<'env> {
    cursor: lmdb::RwCursor<'env>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let env = lmdb::Environment::new()
            .set_max_dbs(MAX_NUM_DBS as u32)
            .set_map_size(config.max_db_size_mbs * MEGABYTE)
            .open_with_permissions(&config.database_path, 0o600)?;
        Ok(Environment { env })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let indexed_attestation_db = self
            .env
            .create_db(Some(INDEXED_ATTESTATION_DB), Self::db_flags())?;
        let indexed_attestation_id_db = self
            .env
            .create_db(Some(INDEXED_ATTESTATION_ID_DB), Self::db_flags())?;
        let attesters_db = self.env.create_db(Some(ATTESTERS_DB), Self::db_flags())?;
        let attesters_max_targets_db = self
            .env
            .create_db(Some(ATTESTERS_MAX_TARGETS_DB), Self::db_flags())?;
        let min_targets_db = self.env.create_db(Some(MIN_TARGETS_DB), Self::db_flags())?;
        let max_targets_db = self.env.create_db(Some(MAX_TARGETS_DB), Self::db_flags())?;
        let current_epochs_db = self
            .env
            .create_db(Some(CURRENT_EPOCHS_DB), Self::db_flags())?;
        let proposers_db = self.env.create_db(Some(PROPOSERS_DB), Self::db_flags())?;
        let metadata_db = self.env.create_db(Some(METADATA_DB), Self::db_flags())?;

        let wrap = |db| {
            crate::Database::Lmdb(Database {
                db,
                _phantom: PhantomData,
            })
        };

        Ok(OpenDatabases {
            indexed_attestation_db: wrap(indexed_attestation_db),
            indexed_attestation_id_db: wrap(indexed_attestation_id_db),
            attesters_db: wrap(attesters_db),
            attesters_max_targets_db: wrap(attesters_max_targets_db),
            min_targets_db: wrap(min_targets_db),
            max_targets_db: wrap(max_targets_db),
            current_epochs_db: wrap(current_epochs_db),
            proposers_db: wrap(proposers_db),
            metadata_db: wrap(metadata_db),
        })
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        let txn = self.env.begin_rw_txn()?;
        Ok(RwTransaction { txn })
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![
            config.database_path.join("data.mdb"),
            config.database_path.join("lock.mdb"),
        ]
    }

    fn db_flags() -> DatabaseFlags {
        DatabaseFlags::default()
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &'env Database,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        Ok(self.txn.get(db.db, key).optional()?.map(Cow::Borrowed))
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        self.txn.put(db.db, &key, &value, Self::write_flags())?;
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        self.txn.del(db.db, &key, None)?;
        Ok(())
    }

    pub fn cursor<'a>(&'a mut self, db: &Database) -> Result<Cursor<'a>, Error> {
        let cursor = self.txn.open_rw_cursor(db.db)?;
        Ok(Cursor { cursor })
    }

    pub fn commit(self) -> Result<(), Error> {
        self.txn.commit()?;
        Ok(())
    }

    fn write_flags() -> WriteFlags {
        WriteFlags::default()
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        let opt_key = self
            .cursor
            .get(None, None, MDB_FIRST)
            .optional()?
            .and_then(|(key, _)| Some(Cow::Borrowed(key?)));
        Ok(opt_key)
    }

    pub fn last_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let opt_key = self
            .cursor
            .get(None, None, MDB_LAST)
            .optional()?
            .and_then(|(key, _)| Some(Cow::Borrowed(key?)));
        Ok(opt_key)
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let opt_key = self
            .cursor
            .get(None, None, MDB_NEXT)
            .optional()?
            .and_then(|(key, _)| Some(Cow::Borrowed(key?)));
        Ok(opt_key)
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        // FIXME: lmdb has an extremely broken API which can mutate the SHARED REFERENCE
        // `value` after `get_current` is called. We need to convert it to a Vec here in order
        // to avoid `value` changing after another cursor operation. I think this represents a bug
        // in the LMDB bindings, as shared references should be immutable.
        if let Some((Some(key), value)) = self.cursor.get(None, None, MDB_GET_CURRENT).optional()? {
            Ok(Some((Cow::Borrowed(key), Cow::Owned(value.to_vec()))))
        } else {
            Ok(None)
        }
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        self.cursor.del(RwTransaction::write_flags())?;
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        self.cursor
            .put(&key, &value, RwTransaction::write_flags())?;
        Ok(())
    }

    pub fn delete_while(
        &mut self,
        f: impl Fn(&[u8]) -> Result<bool, Error>,
    ) -> Result<Vec<Cow<'_, [u8]>>, Error> {
        let mut result = vec![];

        loop {
            let (key_bytes, value) = self.get_current()?.ok_or(Error::MissingKey)?;

            if f(&key_bytes)? {
                result.push(value);
                self.delete_current()?;
                if self.next_key()?.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(result)
    }
}

/// Mix-in trait for loading values from LMDB that may or may not exist.
pub trait TxnOptional<T, E> {
    fn optional(self) -> Result<Option<T>, E>;
}

impl<T> TxnOptional<T, Error> for Result<T, lmdb::Error> {
    fn optional(self) -> Result<Option<T>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
