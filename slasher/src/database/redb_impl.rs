#![cfg(feature = "redb")]
use crate::{
    config::REDB_DATA_FILENAME,
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};
use derivative::Derivative;
use redb::{ReadableTable, TableDefinition};
use std::{borrow::Cow, path::PathBuf};

#[derive(Debug)]
pub struct Environment {
    _db_count: usize,
    db: redb::Database,
}

#[derive(Debug)]
pub struct Database<'env> {
    table_name: String,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RwTransaction<'env> {
    #[derivative(Debug = "ignore")]
    txn: redb::WriteTransaction,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Cursor<'env> {
    #[derivative(Debug = "ignore")]
    txn: &'env redb::WriteTransaction,
    db: &'env Database<'env>,
    current_key: Option<Cow<'env, [u8]>>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let db_path = config.database_path.join(REDB_DATA_FILENAME);
        let database = redb::Database::create(db_path)?;

        Ok(Environment {
            _db_count: MAX_NUM_DBS,
            db: database,
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
        let mut txn = self.db.begin_write()?;
        txn.set_durability(redb::Durability::Eventual);
        Ok(RwTransaction {
            txn,
            _phantom: PhantomData,
        })
    }
}

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &'env Database,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&db.table_name);
        let table = self.txn.open_table(table_definition)?;
        let result = table.get(key.as_ref())?;
        if let Some(access_guard) = result {
            let value = access_guard.value().to_vec();
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
        let mut table = self.txn.open_table(table_definition)?;
        table.insert(key.as_ref(), value.as_ref())?;

        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&db.table_name);
        let mut table = self.txn.open_table(table_definition)?;
        table.remove(key.as_ref())?;

        Ok(())
    }

    pub fn commit(self) -> Result<(), Error> {
        self.txn.commit()?;
        Ok(())
    }

    pub fn cursor<'a>(&'a mut self, db: &'a Database) -> Result<Cursor<'a>, Error> {
        Ok(Cursor {
            txn: &self.txn,
            db,
            current_key: None,
        })
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&self.db.table_name);
        let table = self.txn.open_table(table_definition)?;
        let first = table
            .iter()?
            .next()
            .map(|x| x.map(|(key, _)| key.value().to_vec()));

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
            TableDefinition::new(&self.db.table_name);
        let table = self.txn.open_table(table_definition)?;
        let last = table
            .iter()?
            .next_back()
            .map(|x| x.map(|(key, _)| key.value().to_vec()));

        if let Some(owned_key) = last {
            let owned_key = owned_key?;
            self.current_key = Some(Cow::from(owned_key));
            return Ok(self.current_key.clone());
        }
        Ok(None)
    }

    pub fn get_current(&self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&self.db.table_name);
        let table = self.txn.open_table(table_definition)?;
        if let Some(key) = &self.current_key {
            let result = table.get(key.as_ref())?;

            if let Some(access_guard) = result {
                let value = access_guard.value().to_vec();
                return Ok(Some((key.clone(), Cow::from(value))));
            }
        }
        Ok(None)
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&self.db.table_name);
        let table = self.txn.open_table(table_definition)?;
        if let Some(current_key) = &self.current_key {
            let range: std::ops::RangeFrom<&[u8]> = current_key..;

            let next = table
                .range(range)?
                .next()
                .map(|x| x.map(|(key, _)| key.value().to_vec()));

            if let Some(owned_key) = next {
                let owned_key = owned_key?;
                self.current_key = Some(Cow::from(owned_key));
                return Ok(self.current_key.clone());
            }
        }
        Ok(None)
    }

    pub fn delete_current(&self) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&self.db.table_name);
        let mut table = self.txn.open_table(table_definition)?;
        if let Some(key) = &self.current_key {
            table.remove(key.as_ref())?;
        }
        Ok(())
    }

    pub fn delete_while(
        &self,
        f: impl Fn(&[u8]) -> Result<bool, Error>,
    ) -> Result<Vec<Cow<'_, [u8]>>, Error> {
        let mut deleted_values = vec![];
        if let Some(current_key) = &self.current_key {
            let table_definition: TableDefinition<'_, &[u8], &[u8]> =
                TableDefinition::new(&self.db.table_name);

            let mut table = self.txn.open_table(table_definition)?;

            let deleted =
                table.extract_from_if(current_key.as_ref().., |key, _| f(key).unwrap_or(false))?;

            deleted.for_each(|result| {
                if let Ok(item) = result {
                    let value = item.1.value().to_vec();
                    deleted_values.push(Cow::from(value));
                }
            })
        };
        Ok(deleted_values)
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        let table_definition: TableDefinition<'_, &[u8], &[u8]> =
            TableDefinition::new(&self.db.table_name);
        let mut table = self.txn.open_table(table_definition)?;
        table.insert(key.as_ref(), value.as_ref())?;

        Ok(())
    }
}
