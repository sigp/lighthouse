#![cfg(feature = "mdbx")]

use crate::{
    config::MEGABYTE,
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};
use mdbx::{DatabaseFlags, Geometry, WriteFlags};
use std::borrow::Cow;
use std::ops::Range;
use std::path::PathBuf;

pub const MDBX_GROWTH_STEP: isize = 256 * (1 << 20); // 256 MiB

#[derive(Debug)]
pub struct Environment {
    env: mdbx::Environment<mdbx::NoWriteMap>,
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    txn: mdbx::Transaction<'env, mdbx::RW, mdbx::NoWriteMap>,
}

#[derive(Debug)]
pub struct Database<'env> {
    db: mdbx::Database<'env>,
}

#[derive(Debug)]
pub struct Cursor<'env> {
    cursor: mdbx::Cursor<'env, mdbx::RW>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let env = mdbx::Environment::new()
            .set_max_dbs(MAX_NUM_DBS)
            .set_geometry(Self::geometry(config))
            .open_with_permissions(&config.database_path, 0o600)?;
        Ok(Environment { env })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let txn = self.begin_rw_txn()?;
        txn.create_db(INDEXED_ATTESTATION_DB)?;
        txn.create_db(INDEXED_ATTESTATION_ID_DB)?;
        txn.create_db(ATTESTERS_DB)?;
        txn.create_db(ATTESTERS_MAX_TARGETS_DB)?;
        txn.create_db(MIN_TARGETS_DB)?;
        txn.create_db(MAX_TARGETS_DB)?;
        txn.create_db(CURRENT_EPOCHS_DB)?;
        txn.create_db(PROPOSERS_DB)?;
        txn.create_db(METADATA_DB)?;

        // This is all rather nasty
        let (_, mut databases) = txn.txn.commit_and_rebind_open_dbs()?;
        let mut next_db = || {
            crate::Database::Mdbx(Database {
                db: databases.remove(0),
            })
        };

        Ok(OpenDatabases {
            indexed_attestation_db: next_db(),
            indexed_attestation_id_db: next_db(),
            attesters_db: next_db(),
            attesters_max_targets_db: next_db(),
            min_targets_db: next_db(),
            max_targets_db: next_db(),
            current_epochs_db: next_db(),
            proposers_db: next_db(),
            metadata_db: next_db(),
        })
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        let txn = self.env.begin_rw_txn()?;
        Ok(RwTransaction { txn })
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![
            config.database_path.join("mdbx.dat"),
            config.database_path.join("mdbx.lck"),
        ]
    }

    fn geometry(config: &Config) -> Geometry<Range<usize>> {
        Geometry {
            size: Some(0..config.max_db_size_mbs * MEGABYTE),
            growth_step: Some(MDBX_GROWTH_STEP),
            shrink_threshold: None,
            page_size: None,
        }
    }
}

impl<'env> RwTransaction<'env> {
    pub fn create_db(&self, name: &'static str) -> Result<(), Error> {
        let db = self.txn.create_db(Some(name), Self::db_flags())?;
        self.txn.prime_for_permaopen(db);
        Ok(())
    }

    pub fn open_db(&self, name: &'static str) -> Result<Database, Error> {
        let db = self.txn.open_db(Some(name))?;
        Ok(Database { db })
    }

    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        Ok(self.txn.get(&db.db, key.as_ref())?)
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        self.txn.put(&db.db, key, value, Self::write_flags())?;
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&self, db: &Database, key: K) -> Result<(), Error> {
        self.txn.del(&db.db, key, None)?;
        Ok(())
    }

    pub fn cursor<'a>(&'a self, db: &Database) -> Result<Cursor<'a>, Error> {
        let cursor = self.txn.cursor(&db.db)?;
        Ok(Cursor { cursor })
    }

    pub fn commit(self) -> Result<(), Error> {
        self.txn.commit()?;
        Ok(())
    }

    fn db_flags() -> DatabaseFlags {
        DatabaseFlags::default()
    }

    fn write_flags() -> WriteFlags {
        WriteFlags::default()
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let opt_key = self.cursor.first()?.map(|(key_bytes, ())| key_bytes);
        Ok(opt_key)
    }

    pub fn last_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let opt_key = self.cursor.last()?.map(|(key_bytes, ())| key_bytes);
        Ok(opt_key)
    }

    pub fn next_key(&mut self) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let opt_key = self.cursor.next()?.map(|(key_bytes, ())| key_bytes);
        Ok(opt_key)
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        Ok(self.cursor.get_current()?)
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        self.cursor.del(RwTransaction::write_flags())?;
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        self.cursor
            .put(key.as_ref(), value.as_ref(), RwTransaction::write_flags())?;
        Ok(())
    }
}
