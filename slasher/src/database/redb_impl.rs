#![cfg(feature = "redb")]
use std::fmt;
use std::{
    borrow::{Borrow, Cow},
    path::PathBuf,
};

use redb::{ReadableTable, TableDefinition};

use crate::{
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};

const BASE_DB: &str = "base_db";

#[derive(Debug)]
pub struct Database<'env> {
    table: &'env str,
}

pub struct WriteTransaction<'env>(redb::WriteTransaction<'env>);

impl<'env> fmt::Debug for WriteTransaction<'env> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InternalStruct {{ /* fields and their values */ }}")
    }
}

impl<'env> WriteTransaction<'env> {
    pub fn commit(self) -> std::result::Result<(), redb::CommitError> {
        self.0.commit()
    }
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    txn: Option<WriteTransaction<'env>>,
}

#[derive(Debug)]
pub struct Environment {
    env: PathBuf,
}

#[derive(Debug)]
pub struct Cursor<'env> {
    db: &'env Database<'env>,
    current_key: Option<Cow<'env, [u8]>>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let env = config.database_path.clone();
        Ok(Environment { env })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let indexed_attestation_db = self.create_table(INDEXED_ATTESTATION_DB);
        let indexed_attestation_id_db = self.create_table(INDEXED_ATTESTATION_ID_DB);
        let attesters_db = self.create_table(ATTESTERS_DB);
        let attesters_max_targets_db = self.create_table(ATTESTERS_MAX_TARGETS_DB);
        let min_targets_db = self.create_table(MIN_TARGETS_DB);
        let max_targets_db = self.create_table(MAX_TARGETS_DB);
        let current_epochs_db = self.create_table(CURRENT_EPOCHS_DB);
        let proposers_db = self.create_table(PROPOSERS_DB);
        let metadata_db = self.create_table(METADATA_DB);

        Ok(OpenDatabases {
            indexed_attestation_db,
            indexed_attestation_id_db,
            attesters_db,
            attesters_max_targets_db,
            min_targets_db,
            max_targets_db,
            current_epochs_db,
            proposers_db,
            metadata_db,
        })
    }

    pub fn create_table<'env>(&self, table_name: &'env str) -> crate::Database<'env> {
        crate::Database::Redb(Database { table: table_name })
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![
            config.database_path.join("data.mdb"),
            config.database_path.join("lock.mdb"),
        ]
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        Ok(RwTransaction { txn: None })
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_read().unwrap();
        let table = tx.open_table(table_definition).unwrap();

        let value = table
            .get(key.as_ref().borrow())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        Ok(Some(Cow::from(value)))
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_definition).unwrap();
            table
                .insert(key.as_ref().borrow(), value.as_ref().borrow())
                .unwrap();
        }
        self.txn = Some(WriteTransaction(tx));
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_definition).unwrap();

            table.remove(key.as_ref().borrow()).unwrap();
        }
        self.txn = Some(WriteTransaction(tx));
        Ok(())
    }

    pub fn cursor<'a>(&'a mut self, db: &Database<'a>) -> Result<Cursor<'a>, Error> {
        Ok(Cursor {
            db: db,
            current_key: None,
        })
    }

    pub fn commit(mut self) -> Result<(), Error> {
        match self.txn.unwrap().commit() {
            Ok(_) => {
                self.txn = None;
                Ok(())
            }
            Err(_) => panic!(),
        }
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_read().unwrap();
        let first = tx
            .open_table(table_definition)
            .unwrap()
            .iter()
            .unwrap()
            .next()
            .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

        if let Some(owned_key) = first {
            let owned_key = owned_key.unwrap();
            self.current_key = Some(Cow::from(owned_key));
            Ok(self.current_key.clone())
        } else {
            panic!()
        }
    }

    pub fn last_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_read().unwrap();
        let last = tx
            .open_table(table_definition)
            .unwrap()
            .iter()
            .unwrap()
            .rev()
            .next()
            .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

        if let Some(owned_key) = last {
            let owned_key = owned_key.unwrap();
            self.current_key = Some(Cow::from(owned_key));
            Ok(self.current_key.clone())
        } else {
            panic!()
        }
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_read().unwrap();
        let range: std::ops::RangeFrom<&[u8]> = &self.current_key.clone().unwrap()..;
        let next = tx
            .open_table(table_definition)
            .unwrap()
            .range(range)
            .unwrap()
            .next()
            .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

        if let Some(owned_key) = next {
            let owned_key = owned_key.unwrap();
            self.current_key = Some(Cow::from(owned_key));
            Ok(self.current_key.clone())
        } else {
            panic!()
        }
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_read().unwrap();
        let table = tx.open_table(table_definition).unwrap();
        let value = table
            .get(self.current_key.clone().unwrap().as_ref())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        Ok(Some((
            self.current_key.clone().unwrap().clone(),
            Cow::from(value),
        )))
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_definition).unwrap();
            table
                .remove(self.current_key.clone().unwrap().as_ref().borrow())
                .unwrap();
        }
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = redb::Database::open(BASE_DB).unwrap();
        let tx = database.begin_write().unwrap();
        {
            let mut table = tx.open_table(table_definition).unwrap();
            table
                .insert(key.as_ref().borrow(), value.as_ref().borrow())
                .unwrap();
            // set cursor current key to key
        }
        Ok(())
    }
}
