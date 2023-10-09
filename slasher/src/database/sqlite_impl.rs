#![cfg(feature = "sqlite")]
use r2d2::{PooledConnection, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, ToSql, Transaction, Connection};
use std::{fmt, collections::HashMap};
use derivative::Derivative;
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
    key: Option<Vec<u8>>,
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
    pool: Pool<SqliteConnectionManager>
}

#[derive(Debug)]
pub struct Database<'env> {
    env: &'env Environment,
    table_name: &'env str,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct RwTransaction<'env> {
    db_path: String,
    cursor: HashMap<String, u32>,
    conn: PooledConnection<SqliteConnectionManager>,
    _phantom: PhantomData<&'env ()>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let db_path = match config.database_path.join(BASE_DB).as_path().to_str() {
            Some(path) => path.to_string(),
            None => "".to_string(),
        };
        let manager = SqliteConnectionManager::file(&db_path);
        let pool = r2d2::Pool::builder().build(manager).unwrap();

        Ok(Environment {
            _db_count: MAX_NUM_DBS,
            db_path,
            pool
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

    pub fn db_path(&self) -> String {
        return self.db_path.clone();
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![config.database_path.join(BASE_DB)]
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {

        let conn: PooledConnection<SqliteConnectionManager> = self.pool.get().unwrap();
        conn.pragma_update(None, "journal_mode", "wal");
        conn.pragma_update(None, "synchronous", "NORMAL");
        Ok(RwTransaction {
            _phantom: PhantomData,
            db_path: self.db_path.clone(),
            cursor: HashMap::new(),
            conn,
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

        let txn = self.conn.unchecked_transaction()?;
        let mut stmt = txn.prepare_cached(&query_statement)?;

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
            None => {
                Ok(None)
            },
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
        let txn = self.conn.transaction()?;
        txn.execute(&insert_statement, params![key.as_ref().to_owned(), value.as_ref().to_owned()])?;
        txn.commit()?;
        Ok(())
    }
    
    pub fn del<K: AsRef<[u8]>>(&mut self, db: &Database, key: K) -> Result<(), Error> {
        let delete_statement = format!("DELETE FROM {} WHERE key=?1", db.table_name);
        let txn = self.conn.transaction()?;
        txn.execute(&delete_statement, params![key.as_ref().to_owned()])?;
        txn.commit()?;
        Ok(())
    }

    pub fn delete_current(&mut self, db: &Database) -> Result<(), Error> {
        if let Some(current_id) = self.cursor.get(db.table_name) {
            let delete_statement = format!("DELETE FROM {} WHERE id=?1", db.table_name);
            let txn = self.conn.transaction()?;
            txn.execute(&delete_statement, params![current_id.to_owned()])?;
            txn.commit()?;
            self.cursor.remove(db.table_name);
        }
        Ok(())
    }

    pub fn first_key(&mut self, db: &Database) -> Result<Option<Key>, Error> {
        let query_statement = format!("SELECT MIN(id), key, value FROM {}", db.table_name);
        let txn = self.conn.transaction()?;
        let mut stmt = txn.prepare_cached(&query_statement)?;
        let mut query_result = stmt.query_row([], |row| {
            Ok(FullQueryResult {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })?;

        if let Some(key) = query_result.key {
            self.cursor.insert(db.table_name.to_string(), query_result.id.unwrap_or_default());
            return Ok(Some(Cow::from(key)));
        } 

        Ok(None)
    }

    pub fn last_key(&mut self, db: &Database) -> Result<Option<Key<'env>>, Error> {
        let query_statement = format!("SELECT MAX(id), key, value FROM {}", db.table_name);
        let txn = self.conn.transaction()?;
        let mut stmt = txn.prepare_cached(&query_statement)?;

        let mut query_result = stmt.query_row([], |row| {
            Ok(FullQueryResult {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })?;

        if let Some(key) = query_result.key {
            self.cursor.insert(db.table_name.to_string(), query_result.id.unwrap_or_default());
            return Ok(Some(Cow::from(key)));
        } 

        Ok(None)
    }

    pub fn next_key(&mut self, db: &Database) -> Result<Option<Key<'env>>, Error> {
        
        let mut query_statement = "".to_string();

        let query_result = match self.cursor.get(db.table_name) {
            Some(current_key) => {     
                query_statement = format!(
                    "SELECT MIN(id), key FROM {} where id >?1",
                    db.table_name
                );
                let txn = self.conn.transaction()?;
                let mut stmt = txn.prepare_cached(&query_statement)?;
    
                let mut query_result = stmt.query_row(params![current_key], |row| {
                    Ok(QueryResult {
                        id: row.get(0)?,
                        key: row.get(1)?,
                    })
                })?;

                query_result
            },
            None => {
                query_statement = format!("SELECT MIN(id), key FROM {}", db.table_name);
                let txn = self.conn.transaction()?;
                let mut stmt = txn.prepare_cached(&query_statement)?;
    
                let mut query_result = stmt.query_row([], |row| {
                    Ok(QueryResult {
                        id: row.get(0)?,
                        key: row.get(1)?,
                    })
                })?;

                query_result
            },
        };

        if let Some(key) = query_result.key {
            self.cursor.insert(db.table_name.to_string(), query_result.id.unwrap_or_default());
            return Ok(Some(Cow::from(key)));
        }

        Ok(None)
    }

    pub fn get_current(&mut self, db: &Database) -> Result<Option<(Key<'env>, Value<'env>)>, Error> {
        if let Some(current_id) = self.cursor.get(db.table_name) {
            let query_statement = format!(
                "SELECT id, key, value FROM {} where id=?1",
                db.table_name
            );
            let txn = self.conn.transaction()?;
            let mut stmt = txn.prepare_cached(&query_statement)?;
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

    pub fn delete_while(
        &mut self,
        db: &Database,
        f: impl Fn(&[u8]) -> Result<bool, Error>,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut deleted_values: Vec<Vec<u8>> = vec![];
        if let Some(current_key) = &self.cursor.get(db.table_name) {
            let query_statement = format!(
                "SELECT id, key, value FROM {} where id>=?1",
                db.table_name
            );
           
            let mut stmt = self.conn.prepare(&query_statement)?;
            let rows = stmt.query_map(params![current_key], |row| {
                Ok(FullQueryResult {
                    id: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })?;
            let txn = self.conn.unchecked_transaction()?;
            for row in rows {
                let query_result = row?;
               
                if f(&query_result.key.unwrap())? {
                    let delete_statement = format!("DELETE FROM {} WHERE id=?1", db.table_name);
                    txn.execute(&delete_statement, params![query_result.id.unwrap()])?;
                }
            }
            
            txn.commit()?;
        };
        Ok(deleted_values)
    }

    pub fn commit(mut self) -> Result<(), Error> {
        let txn = self.conn.transaction()?;
        txn.commit()?;
        Ok(())
    }
}