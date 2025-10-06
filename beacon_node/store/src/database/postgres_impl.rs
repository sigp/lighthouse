use sqlx::PgPool;
use std::path::Path;
use std::marker::PhantomData;
use types::EthSpec;

use crate::Error;

pub struct PostgresDB<E: EthSpec> {
    pool: PgPool,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> PostgresDB<E> {
    pub fn open(_path: &Path) -> Result<Self, Error> {
        let url = "postgres://postgres:admin@localhost:5432/store";
        let handle = tokio::runtime::Handle::try_current().map_err(|_| Error::DBError { message: "Tokio runtime not found".into() })?;

        let pool = handle.block_on(async { PgPool::connect(url).await }).map_err(|e| Error::DBError { message: format!("Failed to connect to Postgres: {e}") })?;
        Ok(Self { 
            pool,
            _phantom: PhantomData
        })
    }
}