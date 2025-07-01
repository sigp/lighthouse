use crate::{DBColumn, Error, KeyValueStoreOp, AsyncKeyValueStore};
use sqlx::{PgPool, postgres::PgPoolOptions};
use types::EthSpec;
use std::marker::PhantomData;
use super::interface::WriteOptions;
use async_trait::async_trait;
use std::env;

#[derive(Clone)]
pub struct PostgresDB<E: EthSpec> {
    db: PgPool,
    _phantom: PhantomData<E>
}

impl<E: EthSpec> PostgresDB<E> {
    pub async fn new(database_url: &str) -> Result<Self, Error> {
        let db = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| Error::DBError { message: e.to_string() })?;

        Ok(Self {
            db,
            _phantom: PhantomData
        })
    }
}

#[async_trait]
impl<E: EthSpec> AsyncKeyValueStore<E> for PostgresDB<E> {
    async fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let col = column.as_str();
        let key = key.to_vec();

        sqlx::query_scalar!(
            r#"SELECT value FROM store WHERE col = $1 AND key = $2"#,
            col,
            key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| Error::DBError { message: e.to_string() })
    }

    async fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let col = column.as_str();
        let key = key.to_vec();
        let value = value.to_vec();
        
        sqlx::query!(
            r#"
            INSERT INTO store (col, key, value)
            VALUES ($1, $2, $3)
            ON CONFLICT (col, key) DO UPDATE SET value = EXCLUDED.value
            "#,
            col,
            key,
            value
        )
        .execute(&self.db)
        .await
        .map(|_| ())
        .map_err(|e| Error::DBError { message: e.to_string() })
    }

    // async fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
    //     self.put_bytes(column, key, value).await
    // }

    // async fn sync(&self) -> Result<(), Error> {
    //     Ok(())
    // }

    // async fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
    //     let col = column.as_str();
    //     let key = key.to_vec();

    //     let exists = sqlx::query_scalar!(
    //         r#"SELECT EXISTS(SELECT 1 FROM store WHERE col = $1 AND key = $2)"#,
    //         col,
    //         key
    //     )
    //     .fetch_one(&self.db)
    //     .await
    //     .map_err(|e| Error::DBError { message: e.to_string() })?;

    //     Ok(exists)
    // }

    // async fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
    //     let col = column.as_str();
    //     let key = key.to_vec();

    //     sqlx::query!(
    //         r#"DELETE FROM store WHERE col = $1 AND key = $2"#,
    //         col,
    //         key
    //     )
    //     .execute(&self.db)
    //     .await
    //     .map(|_| ())
    //     .map_err(|e| Error::DBError { message: e.to_string() })?;
    // }

    // async fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
    //     let mut tx = self.db.begin().await.map_err(|e| Error::DBError { message: e.to_string() })?;

    //     for op in batch {
    //         match op {
    //             KeyValueStoreOp::PutKeyValue(col, key, value) => {
    //                 sqlx::query!(
    //                     r#"INSERT INTO store (col, key, value)
    //                     VALUES ($1, $2, $3)
    //                     ON CONFLICT (col, key) DO UPDATE SET VALUE = EXCLUDED.value"#,
    //                     col.as_str(),
    //                     key,
    //                     value
    //                 )
    //                 .execute(&mut tx)
    //                 .await
    //                 .map_err(|e| Error::DBError { message: e.to_string() })?;
    //             }
    //             KeyValueStoreOp::DeleteKey(col, key) => {
    //                 sqlx::query!(
    //                     r#"DELETE FROM store WHERE col = $1 AND key = $2"#,
    //                     col.as_str(),
    //                     key
    //                 )
    //                 .execute(&mut tx)
    //                 .await
    //                 .map_err(|e| Error::DBError { message: e.to_string() })?;
    //             }
    //         }
    //     }
    //     tx.commit().await.map_err(|e| Error::DBError { message: e.to_string() })
    // }
}