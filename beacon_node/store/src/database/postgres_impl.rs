use heck::ToSnakeCase;
use sqlx::{PgPool, Row};
use tokio::runtime::Handle;
use std::path::Path;
use std::marker::PhantomData;
use strum::IntoEnumIterator;
use types::EthSpec;

use crate::{DBColumn, Error};

pub struct PostgresDB<E: EthSpec> {
    pool: PgPool,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PostgresDB<E> {
    pub fn open(_path: &Path) -> Result<Self, Error> {
        let url = "postgres://postgres:admin@localhost:5432/store";
        let handle = tokio::runtime::Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;

        let pool = handle.block_on(async { PgPool::connect(url).await }).map_err(|e| Error::DBError { message: format!("Failed to connect to Postgres: {e}") })?;
        Self::create_tables(&pool)?;
        
        Ok(Self { 
            pool,
            _phantom: PhantomData
        })
    }

    fn create_tables(pool: &PgPool) -> Result<(), Error> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| Error::DBError {message: "Tokio runtime not found".into() })?;

        handle.block_on(async {
            for column in DBColumn::iter() {
                let table = table_name_for_column(column);
                let q = format!("CREATE TABLE IF NOT EXISTS {} (key BYTEA PRIMARY KEY, value BYTEA NOT NULL)", table);
                sqlx::query(&q).execute(pool).await?;
            }
            Ok::<_, sqlx::Error>(())
        })
        .map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let table = table_name_for_column(column);
        let query = format!("SELECT value FROM {} WHERE key = $1", table);

        let handle = Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;

        let row = handle.block_on(async {
            sqlx::query(&query)
                .bind(key)
                .fetch_optional(&self.pool)
                .await
        });

        row.map(|opt| opt.map(|r| r.get::<Vec<u8>, _>("value"))).map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!("INSERT INTO {} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", table);
        let handle = Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;
        let res = handle.block_on(async {
            sqlx::query(&query)
                .bind(key)
                .bind(value)
                .execute(&self.pool)
                .await
        });

        res.map(|_| ()).map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        let table = table_name_for_column(column);
        let query = format!("SELECT EXISTS(SELECT 1 FROM {} WHERE key = $1)", table);

        let handle = Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;

        let result = handle.block_on(async {
            sqlx::query_scalar::<_, bool>(&query)
                .bind(key)
                .fetch_one(&self.pool)
                .await
        });
        result.map_err(|e| Error::DBError { message: e.to_string() })
    }

    pub fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        let table = table_name_for_column(column);
        let query = format!("DELETE FROM {} WHERE key = $1", table);

        let handle = Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;
        let res = handle.block_on(async {
            sqlx::query(&query)
                .bind(key)
                .execute(&self.pool)
                .await
        });

        res.map(|_| ()).map_err(|e| Error::DBError { message: e.to_string() })
    }
}

fn table_name_for_column(column: DBColumn) -> String {
    format!("{:?}", column).to_snake_case()
}

