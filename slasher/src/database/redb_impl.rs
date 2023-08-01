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
pub struct Environment {
    env: PathBuf,
    db_count: usize,
}

#[derive(Debug)]
pub struct Database<'env> {
    table: &'env str,
}

#[derive(Debug)]
pub struct RwTransaction<'env> {
    // txn: Option<redb::WriteTransaction<'env>>,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Debug)]
pub struct Cursor<'env> {
    db: &'env Database<'env>,
    current_key: Option<Cow<'env, [u8]>>,
}

pub struct WriteTransaction<'env>(redb::WriteTransaction<'env>);

impl<'env> Drop for RwTransaction<'env> {
    fn drop(&mut self) {
        // Perform any necessary cleanup or resource deallocation here
        // This code will be automatically executed when an instance of MyStruct goes out of scope.
    }
}

impl<'env> fmt::Debug for WriteTransaction<'env> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InternalStruct {{ /* fields and their values */ }}")
    }
}

impl<'env> WriteTransaction<'env> {
    /*
    pub fn commit(self) -> std::result::Result<(), redb::CommitError> {
        self.0.commit()
    }
    */
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let env = config.database_path.clone();
        Ok(Environment {
            env,
            db_count: MAX_NUM_DBS,
        })
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

    pub fn create_table<'env>(&self, table_name: &'env str) -> crate::Database<'env> {
        crate::Database::Redb(Database { table: table_name })
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![
            config.database_path.join("data.mdb"),
            config.database_path.join("lock.mdb"),
            config.database_path.join(self.env.to_str().unwrap()),
        ]
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        Ok(RwTransaction {
            _phantom: PhantomData,
        })
    }
}

impl<'env> Database<'env> {
    fn open_database(&'env self) -> Result<redb::Database, Error> {
        match redb::Database::open(BASE_DB) {
            Ok(db) => Ok(db),
            Err(e) => Err(Error::DatabaseRedbError(e.into())),
        }
    }

    fn create_write_transaction(
        &'env self,
        database: &'env redb::Database,
    ) -> Result<redb::WriteTransaction, Error> {
        match database.begin_write() {
            Ok(transaction) => Ok(transaction),
            Err(e) => return Err(Error::DatabaseRedbError(e.into())),
        }
    }

    fn create_read_transaction(
        &self,
        database: &'env redb::Database,
    ) -> Result<redb::ReadTransaction, Error> {
        match database.begin_read() {
            Ok(transaction) => Ok(transaction),
            Err(e) => Err(Error::DatabaseRedbError(e.into())),
        }
    }

    fn open_write_table(
        &'env self,
        tx: &'env redb::WriteTransaction,
    ) -> Result<redb::Table<'env, 'env, &'env [u8], &'env [u8]>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(self.table);
        match tx.open_table(table_definition) {
            Ok(table) => Ok(table),
            Err(e) => Err(Error::DatabaseRedbError(e.into())),
        }
    }

    fn open_read_table(
        &self,
        tx: &'env redb::ReadTransaction<'env>,
    ) -> Result<redb::ReadOnlyTable<'env, &'env [u8], &'env [u8]>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.table.clone());
        match tx.open_table(table_definition) {
            Ok(table) => Ok(table),
            Err(e) => Err(Error::DatabaseRedbError(e.into())),
        }
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = db.open_database()?;
        let tx = db.create_write_transaction(&database)?;
        // let table = db.open_write_table(&tx)?;
        let table = tx.open_table(table_definition).unwrap();
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
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = db.open_database()?;
        let tx = db.create_write_transaction(&database)?;
        {
            let mut table = tx.open_table(table_definition).unwrap();
            table
                .insert(key.as_ref().borrow(), value.as_ref().borrow())
                .unwrap();
        }
        // self.txn = Some(&WriteTransaction(tx));
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(db.table);
        let database = db.open_database()?;
        let tx = db.create_write_transaction(&database)?;
        {
            let mut table = tx.open_table(table_definition).unwrap();

            table.remove(key.as_ref().borrow()).unwrap();
        }
        // self.txn = Some(&WriteTransaction(tx));
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
            TableDefinition::new(self.db.table);
        let database = self.db.open_database()?;
        let tx = self.db.create_read_transaction(&database)?;

        let table = tx.open_table(table_definition).unwrap();

        let first = match table.iter() {
            Ok(mut iterator) => iterator
                .next()
                .map(|x| x.map(|(key, _)| (key.value()).to_vec())),
            Err(e) => return Err(Error::DatabaseRedbError(e.into())),
        };

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
        let database = self.db.open_database()?;
        let tx = self.db.create_read_transaction(&database)?;

        let table = tx.open_table(table_definition).unwrap();

        let last = match table.iter() {
            Ok(iterator) => iterator
                .rev()
                .next_back()
                .map(|x| x.map(|(key, _)| (key.value()).to_vec())),
            Err(e) => return Err(Error::DatabaseRedbError(e.into())),
        };

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
        let database = self.db.open_database()?;
        let tx = self.db.create_read_transaction(&database)?;
        let range: std::ops::RangeFrom<&[u8]> = &self.current_key.clone().unwrap()..;

        let table = tx.open_table(table_definition).unwrap();

        let next = match table.range(range) {
            Ok(mut range) => range
                .next()
                .map(|x| x.map(|(key, _)| (key.value()).to_vec())),
            Err(e) => return Err(Error::DatabaseRedbError(e.into())),
        };

        if let Some(owned_key) = next {
            let owned_key = owned_key.unwrap();
            self.current_key = Some(Cow::from(owned_key));
            Ok(self.current_key.clone())
        } else {
            Ok(None)
        }
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        if let Some(key) = &self.current_key {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(self.db.table);
            let database = self.db.open_database()?;
            let tx = self.db.create_read_transaction(&database)?;
            let table = tx.open_table(table_definition).unwrap();
            let result = table.get(key.as_ref());
            let value = match result {
                Ok(res) => {
                    if let Some(access_guard) = res {
                        access_guard.value().to_vec().clone()
                    } else {
                        return Ok(None);
                    }
                }
                Err(e) => return Err(Error::DatabaseRedbError(e.into())),
            };
            Ok(Some((key.clone(), Cow::from(value))))
        } else {
            Ok(None)
        }
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        if let Some(key) = &self.current_key {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(self.db.table);
            let database = self.db.open_database()?;
            let tx = self.db.create_write_transaction(&database)?;
            {
                let mut table = tx.open_table(table_definition).unwrap();
                match table.remove(key.as_ref()) {
                    Ok(_) => return Ok(()),
                    Err(e) => return Err(Error::DatabaseRedbError(e.into())),
                };
            }
        } else {
            Ok(())
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(self.db.table);
        let database = self.db.open_database()?;
        let tx = self.db.create_write_transaction(&database)?;
        {
            let mut table = tx.open_table(table_definition).unwrap();
            match table.insert(key.as_ref().borrow(), value.as_ref().borrow()) {
                Ok(_) => return Ok(()),
                Err(e) => return Err(Error::DatabaseRedbError(e.into())),
            };
        }
    }
}
