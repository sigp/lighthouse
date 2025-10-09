use heck::ToSnakeCase;
use once_cell::sync::Lazy;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tokio::runtime::{Handle, Runtime};
use std::path::Path;
use std::marker::PhantomData;
use std::time::Duration;
use strum::IntoEnumIterator;
use types::EthSpec;

use crate::{DBColumn, Error};

static GLOBAL_RT: Lazy<Runtime> = Lazy::new(|| {
    Runtime::new().expect("Failed to create global tokio runtime for PostgresDB")
});

pub struct PostgresDB<E: EthSpec> {
    pool: PgPool,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PostgresDB<E> {
    pub fn open(_path: &Path) -> Result<Self, Error> {
        let url = "postgres://postgres:admin@localhost:5432/store";

        let pool = block_on_in_runtime(async {
            PgPoolOptions::new()
                .max_connections(90)
                .acquire_timeout(Duration::from_secs(30))
                .connect(url)
                .await
                .map_err(|e| Error::DBError { message: format!("Failed to connect to Postgres: {:?}", e) })
        })??;
        
        Self::create_tables(&pool)?;
        Ok(Self { pool, _phantom: PhantomData})
    }

    fn create_tables(pool: &PgPool) -> Result<(), Error> {
        block_on_in_runtime(async {
            for column in DBColumn::iter() {
                let table = table_name_for_column(column);
                let q = format!("CREATE TABLE IF NOT EXISTS {} (key BYTEA PRIMARY KEY, value BYTEA NOT NULL)", table);
                sqlx::query(&q).execute(pool).await?;
            }
            Ok::<_, sqlx::Error>(())
        })?
        .map_err(|e| Error::DBError { message: e.to_string() })
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
        .map_err(|e| Error::DBError { message: format!("{:?}", e) })?;

        Ok(row.map(|r| r.get::<Vec<u8>, _>("value")))
    }

    pub fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!("INSERT INTO {} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", table);

        block_on_in_runtime(async {
            sqlx::query(&query)
                .bind(key)
                .bind(value)
                .execute(&self.pool)
                .await
        })?
        .map(|_| ())
        .map_err(|e| Error::DBError { message: format!("{:?}", e) })
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
        .map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!("DELETE FROM {} WHERE key = $1", table);

        block_on_in_runtime(async {
            sqlx::query(&query)
                .bind(key)
                .execute(&self.pool)
                .await
        })
        .map(|_| ())
        .map_err(|e| Error::DBError { message: format!("{:?}", e) })
    }
}

fn table_name_for_column(column: DBColumn) -> String {
    format!("{:?}", column).to_snake_case()
}

fn block_on_in_runtime<F: std::future::Future>(fut: F) -> Result<F::Output, Error> {
    // match Handle::try_current() {
    //     Ok(handle) => Ok(handle.block_on(fut)),
    //     Err(_) => {
    //         let rt = Runtime::new().map_err(|e| Error::DBError { message: e.to_string() })?;
    //         Ok(rt.block_on(fut))
    //     }
    // }
    Ok(GLOBAL_RT.block_on(fut))
}

