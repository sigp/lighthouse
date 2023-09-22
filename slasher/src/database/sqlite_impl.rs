#![cfg(feature = "sqlite")]
use rusqlite::{params, OptionalExtension, ToSql};
use std::fmt;
use std::{
    borrow::{Borrow, Cow},
    path::PathBuf,
};

use crate::{
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};

const BASE_DB: &str = "slasher_db";

impl<'env> Database<'env> {}

struct QueryResult {
    id: Option<u32>,
    value: Option<Vec<u8>>,
}

struct FullQueryResult {
    id: Option<u32>,
    key: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Environment {
    _db_count: usize,
    db_path: String,
}

#[derive(Debug)]
pub struct Database<'env> {
    env: &'env Environment,
    table_name: &'env str,
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
    current_id: Option<u32>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let db_path = match config.database_path.join(BASE_DB).as_path().to_str() {
            Some(path) => path.to_string(),
            None => "".to_string(),
        };
        let _ = rusqlite::Connection::open(&db_path)?;

        Ok(Environment {
            _db_count: MAX_NUM_DBS,
            db_path,
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
        let create_table_command = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                key   BLOB UNIQUE,
                value BLOB
            );",
            table_name
        );

        let database = rusqlite::Connection::open(&self.db_path)?;

        database.execute(&create_table_command, ())?;

        Ok(crate::Database::Sqlite(Database {
            table_name,
            env: self,
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

impl<'env> RwTransaction<'env> {
    pub fn get<K: AsRef<[u8]> + ?Sized>(
        &'env self,
        db: &Database<'env>,
        key: &K,
    ) -> Result<Option<Cow<'env, [u8]>>, Error> {
        let query_statement = format!("SELECT * FROM {} where key =:key;", db.table_name);
        let database = rusqlite::Connection::open(&db.env.db_path)?;
        let mut stmt = database.prepare_cached(&query_statement)?;

        let query_result = stmt
            .query_row([key.as_ref()], |row| {
                Ok(FullQueryResult {
                    id: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })
            .optional()?;

        match query_result {
            Some(result) => Ok(Some(Cow::from(result.value.unwrap_or_default()))),
            None => Ok(None),
        }
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db: &Database,
        key: K,
        value: V,
    ) -> Result<(), Error> {
        let insert_statement = format!(
            "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
            db.table_name
        );
        let database = rusqlite::Connection::open(&db.env.db_path)?;
        let mut stmt = database.prepare_cached(&insert_statement)?;
        stmt.execute(params![key.as_ref(), value.as_ref()])?;
        Ok(())
    }

    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let delete_statement = format!("DELETE FROM {} WHERE key=?1", db.table_name);
        let database = rusqlite::Connection::open(&db.env.db_path)?;
        let mut stmt = database.prepare_cached(&delete_statement)?;
        stmt.execute(params![key.as_ref()])?;
        Ok(())
    }

    pub fn cursor<'a>(&'a mut self, db: &'a Database) -> Result<Cursor<'a>, Error> {
        Ok(Cursor {
            db,
            current_id: None,
        })
    }

    pub fn commit(self) -> Result<(), Error> {
        Ok(())
    }
}

impl<'env> Cursor<'env> {
    pub fn first_key(&mut self) -> Result<Option<Key>, Error> {
        let query_statement = format!("SELECT MIN(id), key, value FROM {}", self.db.table_name);
        let database = rusqlite::Connection::open(&self.db.env.db_path)?;
        let mut stmt = database.prepare_cached(&query_statement)?;
        let mut query_result = stmt.query_row([], |row| {
            Ok(FullQueryResult {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })?;

        if query_result.id.is_some() {
            let key = Cow::from(query_result.key.unwrap_or_default());
            self.current_id = query_result.id;
            return Ok(Some(key));
        }
        Ok(None)
    }

    pub fn last_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let query_statement = format!("SELECT MAX(id), key, value FROM {}", self.db.table_name);
        let database = rusqlite::Connection::open(&self.db.env.db_path)?;
        let mut stmt = database.prepare_cached(&query_statement)?;

        let mut query_result = stmt.query_row([], |row| {
            Ok(FullQueryResult {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })?;

        if query_result.id.is_some() {
            let key = Cow::from(query_result.key.unwrap_or_default());
            self.current_id = query_result.id;
            return Ok(Some(key));
        }
        Ok(None)
    }

    pub fn next_key(&mut self) -> Result<Option<Key<'env>>, Error> {
        let mut query_statement = "".to_string();
        if let Some(current_id) = &self.current_id {
            query_statement = format!(
                "SELECT MIN(id), key FROM {} where id > {}",
                self.db.table_name, current_id
            );
        } else {
            query_statement = format!("SELECT MIN(id), key FROM {}", self.db.table_name);
        }
        let database = rusqlite::Connection::open(&self.db.env.db_path)?;
        let mut stmt = database.prepare_cached(&query_statement)?;

        let mut query_result = stmt.query_row([], |row| {
            Ok(QueryResult {
                id: row.get(0)?,
                value: row.get(1)?,
            })
        })?;

        if query_result.id.is_some() {
            let key = Cow::from(query_result.value.unwrap_or_default());
            self.current_id = query_result.id;
            return Ok(Some(key));
        }
        Ok(None)
    }

    pub fn get_current(&mut self) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        if let Some(current_id) = &self.current_id {
            let query_statement = format!(
                "SELECT id, key, value FROM {} where id=?1",
                self.db.table_name
            );
            let database = rusqlite::Connection::open(&self.db.env.db_path)?;
            let mut stmt = database.prepare_cached(&query_statement)?;
            let query_result = stmt
                .query_row([current_id], |row| {
                    Ok(FullQueryResult {
                        id: row.get(0)?,
                        key: row.get(1)?,
                        value: row.get(2)?,
                    })
                })
                .optional()?;

            if let Some(result) = query_result {
                return Ok(Some((
                    Cow::from(result.key.unwrap_or_default()),
                    Cow::from(result.value.unwrap_or_default()),
                )));
            }
        }
        Ok(None)
    }

    pub fn delete_current(&mut self) -> Result<(), Error> {
        if let Some(current_id) = &self.current_id {
            let delete_statement = format!("DELETE FROM {} WHERE id=?1", self.db.table_name);
            let database = rusqlite::Connection::open(&self.db.env.db_path)?;
            let _ = database.execute(&delete_statement, [current_id])?;
            self.current_id = None;
        }
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<(), Error> {
        let insert_statement = format!(
            "INSERT OR REPLACE INTO {} (key, value) VALUES (?1, ?2)",
            self.db.table_name
        );
        let database = rusqlite::Connection::open(&self.db.env.db_path)?;
        let mut stmt = database.prepare_cached(&insert_statement)?;
        stmt.execute(params![key.as_ref(), value.as_ref()])?;
        Ok(())
    }
}
