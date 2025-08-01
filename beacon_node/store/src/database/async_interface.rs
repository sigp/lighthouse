use crate::{DBColumn, Error};
use async_trait::async_trait;
use types::EthSpec;

#[async_trait]
pub trait AsyncKeyValueStore<E: EthSpec>: Send + Sync {
    async fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    async fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error>;
    async fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error>;
    // async fn sync(&self) -> Result<(), Error>;
    // async fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error>;
    // async fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error>;
    // async fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error>;
}