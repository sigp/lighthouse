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
    database_path: PathBuf,
    db_count: usize,
}

#[derive(Debug)]
pub struct Database<'env> {
    table_name: &'env str,
    db_path: String,
    db: redb::Database,
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    // txn: Option<redb::WriteTransaction<'env>>,
    _phantom: PhantomData<&'env ()>,
}

impl<'env> Drop for RwTransaction<'env> {
    fn drop(&mut self) {
        // Perform any necessary cleanup or resource deallocation here
        // This code will be automatically executed when an instance of MyStruct goes out of scope.
    }
}

#[derive(Debug)]
pub struct Cursor<'env> {
    db: &'env Database<'env>,
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
        Ok(Environment {
            database_path: config.database_path.clone(),
            db_count: MAX_NUM_DBS,
        })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let indexed_attestation_db =
            self.create_table(INDEXED_ATTESTATION_DB, self.database_path.clone())?;
        let indexed_attestation_id_db =
            self.create_table(INDEXED_ATTESTATION_ID_DB, self.database_path.clone())?;
        let attesters_db = self.create_table(ATTESTERS_DB, self.database_path.clone())?;
        let attesters_max_targets_db =
            self.create_table(ATTESTERS_MAX_TARGETS_DB, self.database_path.clone())?;
        let min_targets_db = self.create_table(MIN_TARGETS_DB, self.database_path.clone())?;
        let max_targets_db = self.create_table(MAX_TARGETS_DB, self.database_path.clone())?;
        let current_epochs_db = self.create_table(CURRENT_EPOCHS_DB, self.database_path.clone())?;
        let proposers_db = self.create_table(PROPOSERS_DB, self.database_path.clone())?;
        let metadata_db = self.create_table(METADATA_DB, self.database_path.clone())?;

        if self.db_count != 9 {
            panic!();
        }

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
        &self,
        table_name: &'env str,
        file_path: PathBuf,
    ) -> Result<crate::Database<'env>, Error> {
        let db_path = match file_path.join(table_name).as_path().to_str() {
            Some(path) => path.to_string(),
            None => "".to_string(),
        };

        // opening the table for the first time
        let database = redb::Database::create(&db_path)?;

        Ok(crate::Database::Redb(Database {
            table_name,
            db_path,
            db: database,
        }))
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![config.database_path.join(BASE_DB)]
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        Ok(RwTransaction {
            _phantom: PhantomData,
        })
    }
}

impl<'env> Database<'env> {
    fn open_database(&'env self) -> Result<redb::Database, redb::DatabaseError> {
        redb::Database::create(&self.db_path)
    }

    /*

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
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(db.table_name);
        let database = &db.db;
        let tx = database.begin_write()?;
        let table = tx.open_table(table_definition)?;
        let result = table.get(key.as_ref().borrow());
        match result {
            Ok(res) => {
                if let Some(access_guard) = res {
                    let value = access_guard.value().to_vec().clone();
                    Ok(Some(Cow::from(value)))
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(Error::DatabaseRedbError(e.into())),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(db.table_name);
        let database = &db.db;
        let tx = database.begin_write()?;
        {
            let mut table = tx.open_table(table_definition)?;
            table.insert(key.as_ref().borrow(), value.as_ref().borrow())?;
        }
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(db.table_name);
        let database = &db.db;
        let tx = database.begin_write()?;
        {
            let mut table = tx.open_table(table_definition)?;
            table.remove(key.as_ref().borrow())?;
        }
        Ok(())
    }

    pub fn cursor<'a>(&'a mut self, db: &'a Database<'a>) -> Result<Cursor<'a>, Error> {
        Ok(Cursor {
            db,
            current_key: None,
        })
    }

    pub fn commit(self) -> Result<(), Error> {
        Ok(())
        /*
        match self.txn.unwrap().commit() {
            Ok(_) => {
                self.txn = None;
                Ok(())
            }
            Err(_) => panic!(),
        }*/
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table_name);
        let database = &self.db.db;
        let tx = database.begin_write()?;

        let table = tx.open_table(table_definition)?;

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
            TableDefinition::new(self.db.table_name);
        let database = &self.db.db;
        let tx = database.begin_write()?;

        let table = tx.open_table(table_definition)?;

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
            TableDefinition::new(self.db.table_name);
        let database = &self.db.db;
        let tx = database.begin_write()?;

        if let Some(current_key) = &self.current_key.clone() {
            let range: std::ops::RangeFrom<&[u8]> = current_key..;
            let table = tx.open_table(table_definition)?;

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
        if let Some(key) = &self.current_key {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(self.db.table_name);
            let database = &self.db.db;
            let tx = database.begin_write()?;
            let table = tx.open_table(table_definition)?;
            let result = table.get(key.as_ref())?;

            if let Some(access_guard) = result {
                let value = access_guard.value().to_vec().clone();
                return Ok(Some((key.clone(), Cow::from(value))));
            }
        }
        Ok(None)
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        if let Some(key) = &self.current_key {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(self.db.table_name);
            let database = &self.db.db;
            let tx = database.begin_write()?;
            {
                let mut table = tx.open_table(table_definition)?;
                table.remove(key.as_ref())?;
            }
        }
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table_name);
        let database = &self.db.db;
        let tx = database.begin_write()?;
        {
            let mut table = tx.open_table(table_definition)?;
            table.insert(key.as_ref().borrow(), value.as_ref().borrow())?;
        }
        Ok(())
    }
}
