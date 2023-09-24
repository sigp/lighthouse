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

const BASE_DB: &str = "slasher_db";

#[derive(Debug)]
pub struct Environment {
    _db_count: usize,
    db_path: String,
    db: redb::Database,
}

#[derive(Debug)]
pub struct Database<'env> {
    table_name: String,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    txn: WriteTransaction<'env>,
    db: &'env redb::Database,
}


#[derive(Debug)]
pub struct Cursor<'env> {
    txn: &'env WriteTransaction<'env>,
    table_name: String,
    current_key: Option<Cow<'env, [u8]>>,
}

pub struct WriteTransaction<'env>(redb::WriteTransaction<'env>);

impl<'env> fmt::Debug for WriteTransaction<'env> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InternalStruct {{ /* fields and their values */ }}")
    }
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let db_path = match config.database_path.join(BASE_DB).as_path().to_str() {
            Some(path) => path.to_string(),
            None => "".to_string(),
        };

        let database = redb::Database::create(db_path.clone())?;

        Ok(Environment {
            _db_count: MAX_NUM_DBS,
            db_path,
            db: database
        })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let indexed_attestation_db = self.create_table(INDEXED_ATTESTATION_DB)?;
        let indexed_attestation_id_db = self.create_table(INDEXED_ATTESTATION_ID_DB)?;
        let attesters_db = self.create_table(ATTESTERS_DB)?;
        let attesters_max_targets_db = self.create_table(ATTESTERS_MAX_TARGETS_DB)?;
        let min_targets_db = self.create_table(MIN_TARGETS_DB)?;
        let max_targets_db = self.create_table(MAX_TARGETS_DB)?;
        let current_epochs_db = self.create_table(CURRENT_EPOCHS_DB)?;
        let proposers_db = self.create_table(PROPOSERS_DB)?;
        let metadata_db = self.create_table(METADATA_DB)?;

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

    pub fn create_table<'env>(
        &'env self,
        table_name: &'env str,
    ) -> Result<crate::Database<'env>, Error> {
        // need to create the table via opening in write mode
        // so we can open it in read mode later
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(table_name);
        let tx = self.db.begin_write()?;
        tx.open_table(table_definition)?;
        tx.commit()?;

        Ok(crate::Database::Redb(Database {
            table_name: table_name.to_string(),
            _phantom: PhantomData,
        }))
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![config.database_path.join(BASE_DB)]
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        Ok(RwTransaction {
            txn: WriteTransaction(self.db.begin_write()?),
            db: &self.db,
        })
    }
}

impl<'env> Database<'env> {
    /*
    fn open_database(&'env self) -> Result<redb::Database, redb::DatabaseError> {
        redb::Database::create(&self.db_path)
    }

     fn open_write_table<'a>(
         table_name: &str,
         tx: &'a redb::WriteTransaction,
     ) -> Result<redb::Table<'a, 'a, &'a[u8], &'a[u8]>, redb::TableError> {
         let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(table_name);
         tx.open_table(table_definition)
     }

    fn open_write_table<'a>(
         table_name: &str,
         tx: &'a redb::ReadTransaction,
     ) -> Result<redb::Table<'a, 'a, &'a[u8], &'a[u8]>, redb::TableError> {
         let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(table_name);
         tx.open_table(table_definition)
     }
      */
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &self,
        db: &Database,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&db.table_name);
        let table = self.txn.0.open_table(table_definition)?;
        let result = table.get(key.as_ref().borrow())?;
        if let Some(access_guard) = result {
            let value = access_guard.value().to_vec().clone();
            Ok(Some(Cow::from(value)))
        } else {
            Ok(None)
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&db.table_name);
        let mut table = self.txn.0.open_table(table_definition)?;
        table.insert(key.as_ref().borrow(), value.as_ref().borrow())?;
      
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&db.table_name);
        let mut table = self.txn.0.open_table(table_definition)?;
        table.remove(key.as_ref().borrow())?;

        Ok(())
    }

    pub fn cursor<'a:'env>(&'a self, db: &Database) -> Result<Cursor<'a>, Error> {
        // let txn = WriteTransaction(self.db.begin_write()?);
        Ok(Cursor {
            current_key: None,
            txn: &self.txn,
            table_name: db.table_name.clone()
        })
    }

    pub fn commit(self) -> Result<(), Error> {
        self.txn.0.commit()?;
        Ok(())
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {

        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);
        let table = self.txn.0.open_table(table_definition)?;

        let first = table
            .iter()?
            .next()
            .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

        if let Some(owned_key) = first {
            let owned_key = owned_key?;
            self.current_key = Some(Cow::from(owned_key));
            Ok(self.current_key.clone())
        } else {
            Ok(None)
        }
    }

    pub fn last_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);
        let table = self.txn.0.open_table(table_definition)?;

        let last = table
            .iter()?
            .rev()
            .next_back()
            .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

        if let Some(owned_key) = last {
            let owned_key = owned_key?;
            self.current_key = Some(Cow::from(owned_key));
            return Ok(self.current_key.clone());
        }
        Ok(None)
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {

        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);

        if let Some(current_key) = &self.current_key.clone() {
            let range: std::ops::RangeFrom<&[u8]> = current_key..;

            let table = self.txn.0.open_table(table_definition)?;
            let next = table
                .range(range)?
                .next()
                .map(|x| x.map(|(key, _)| (key.value()).to_vec()));

            if let Some(owned_key) = next {
                let owned_key = owned_key?;
                self.current_key = Some(Cow::from(owned_key));
                return Ok(self.current_key.clone());
            }
        }
        Ok(None)
    } 

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);
        if let Some(key) = &self.current_key {
            let table = self.txn.0.open_table(table_definition)?;
            let result = table.get(key.as_ref())?;

            if let Some(access_guard) = result {
                let value = access_guard.value().to_vec().clone();
                return Ok(Some((key.clone(), Cow::from(value))));
            }
        }
        Ok(None)
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);
        if let Some(key) = &self.current_key {
            let mut table = self.txn.0.open_table(table_definition)?;
            table.remove(key.as_ref())?;
        }
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        println!("CURSOR PRINT");
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
        TableDefinition::new(&self.table_name);
        let mut table = self.txn.0.open_table(table_definition)?;
        table.insert(key.as_ref().borrow(), value.as_ref().borrow())?;
        Ok(())
    }
}
