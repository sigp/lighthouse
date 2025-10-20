use crate::{ColumnIter, ColumnKeyIter, DBColumn, Error, Key, KeyValueStoreOp};
use heck::ToSnakeCase;
use once_cell::sync::Lazy;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::future::Future;
use std::iter::once;
use std::marker::PhantomData;
use std::path::Path;
use std::time::Duration;
use strum::IntoEnumIterator;
use tokio::runtime::{Handle, Runtime};
use types::EthSpec;

static GLOBAL_RT: Lazy<Runtime> =
    Lazy::new(|| Runtime::new().expect("Failed to create global tokio runtime for PostgresDB"));

pub struct PostgresDB<E: EthSpec> {
    pool: PgPool,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PostgresDB<E> {
    pub fn open(_path: &Path) -> Result<Self, Error> {
        let url = "postgres://postgres:admin@localhost:5432/store";

        let pool = block_on_in_runtime(async {
            PgPoolOptions::new()
                .max_connections(50)
                .acquire_timeout(Duration::from_secs(30))
                .connect(url)
                .await
                .map_err(|e| Error::DBError {
                    message: format!("Failed to connect to Postgres: {:?}", e),
                })
        })??;

        Self::create_tables(&pool)?;
        Ok(Self {
            pool,
            _phantom: PhantomData,
        })
    }

    fn create_tables(pool: &PgPool) -> Result<(), Error> {
        block_on_in_runtime(async {
            for column in DBColumn::iter() {
                let table = table_name_for_column(column);
                let q = format!(
                    "CREATE TABLE IF NOT EXISTS {} (key BYTEA PRIMARY KEY, value BYTEA NOT NULL)",
                    table
                );
                sqlx::query(&q).execute(pool).await?;
            }
            Ok::<_, sqlx::Error>(())
        })?
        .map_err(|e| Error::DBError {
            message: e.to_string(),
        })
    }

    pub fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let table = table_name_for_column(column);
        let query = format!("SELECT value FROM {} WHERE key = $1", table);

        let row = block_on_in_runtime(async {
            sqlx::query(&query)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
        })?
        .map_err(|e| Error::DBError {
            message: format!("{:?}", e),
        })?;

        Ok(row.map(|r| r.get::<Vec<u8>, _>("value")))
    }

    pub fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!(
            "INSERT INTO {} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            table
        );

        block_on_in_runtime(async {
            sqlx::query(&query)
                .bind(key)
                .bind(value)
                .execute(&self.pool)
                .await
        })?
        .map(|_| ())
        .map_err(|e| Error::DBError {
            message: format!("{:?}", e),
        })
    }

    pub fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        let table = table_name_for_column(column);
        let query = format!("SELECT EXISTS(SELECT 1 FROM {} WHERE key = $1)", table);

        block_on_in_runtime(async {
            sqlx::query_scalar::<_, bool>(&query)
                .bind(key)
                .fetch_one(&self.pool)
                .await
        })?
        .map_err(|e| Error::DBError {
            message: e.to_string(),
        })
    }

    pub fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!("DELETE FROM {} WHERE key = $1", table);

        block_on_in_runtime(async { sqlx::query(&query).bind(key).execute(&self.pool).await })
            .map(|_| ())
            .map_err(|e| Error::DBError {
                message: format!("{:?}", e),
            })
    }

    pub fn do_atomically(&self, ops: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        block_on_in_runtime(async {
            let mut tx = self.pool.begin().await.map_err(|e| Error::DBError {
                message: format!("{:?}", e),
            })?;

            for op in ops {
                match op {
                    KeyValueStoreOp::PutKeyValue(col, key, value) => {
                        let table = table_name_for_column(col);
                        let q = format!(
                            "INSERT INTO {} (key, value) VALUES ($1, $2)
                            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                            table
                        );
                        sqlx::query(&q)
                            .bind(&key)
                            .bind(&value)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| Error::DBError {
                                message: format!("{:?}", e),
                            })?;
                    }
                    KeyValueStoreOp::DeleteKey(col, key) => {
                        let table = table_name_for_column(col);
                        let q = format!("DELETE FROM {} WHERE key = $1", table);
                        sqlx::query(&q)
                            .bind(&key)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| Error::DBError {
                                message: format!("{:?}", e),
                            })?;
                    }
                }
            }

            tx.commit().await.map_err(|e| Error::DBError {
                message: format!("{:?}", e),
            })?;

            Ok::<(), Error>(())
        })?
    }

    pub fn iter_column_from<K: Key>(
        &self, 
        column: DBColumn, 
        from: &[u8]
    ) -> ColumnIter<'_, K> {
        let table = table_name_for_column(column);
        let query = format!("SELECT Key, value FROM {} WHERE >= $1 ORDER BY key ASC", table);

        let row_results: Result<Vec<(Vec<u8>, Vec<u8>)>, Error> = block_on_in_runtime(async {
            let rows = sqlx::query(&query)
                .bind(from)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| Error::DBError {
                    message: format!("{:?}", e),
                })?;

            Ok(rows
                .into_iter()
                .map(|row| {
                    let k: Vec<u8> = row.get("key");
                    let v: Vec<u8> = row.get("value");
                    Ok((k, v))
                })
                .collect::<Result<Vec<_>, Error>>()?)
        }).and_then(|r| r);

        match row_results {
            Ok(rows) => {
                let iter = rows.into_iter().map(|(k_bytes, v)| {
                    let k = K::from_bytes(&k_bytes)?;
                    Ok((k, v))
                });
                Box::new(iter)
            }
            Err(e) => Box::new(once(Err(e)))
        }
    }

    pub fn iter_column_keys_from<K: Key>(
        &self,
        column: DBColumn,
        from: &[u8],
    ) -> ColumnKeyIter<'_, K> {
        let table = table_name_for_column(column);
        let query = format!("SELECT key FROM {} WHERE key >= $1 ORDER BY key ASC", table);

        let rows_result: Result<Vec<Vec<u8>>, Error> = block_on_in_runtime(async {
            let rows = sqlx::query(&query)
                .bind(from)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| Error::DBError { message: format!("{:?}", e) })?;

            Ok(rows
                .into_iter()
                .map(|row| {
                    let k: Vec<u8> = row.get("key");
                    Ok(k)
                })
                .collect::<Result<Vec<_>, Error>>()?)
        }).and_then(|r| r);

        match rows_result {
            Ok(keys) => {
                let iter = keys.into_iter().map(|k_bytes| {
                    let k = K::from_bytes(&k_bytes)?;
                    Ok(k)
                    
                });
                Box::new(iter)
            }
            Err(e) => Box::new(once(Err(e)))
        }
    }
}

fn table_name_for_column(column: DBColumn) -> String {
    format!("{:?}", column).to_snake_case()
}

fn block_on_in_runtime<F: Future>(fut: F) -> Result<F::Output, Error> {
    match Handle::try_current() {
        Ok(handle) => Ok(tokio::task::block_in_place(|| handle.block_on(fut))),
        Err(_) => Ok(GLOBAL_RT.block_on(fut)),
    }
}
