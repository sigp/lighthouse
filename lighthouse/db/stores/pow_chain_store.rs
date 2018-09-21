use std::sync::Arc;
use super::{
    ClientDB,
    DBError,
};
use super::POW_CHAIN_DB_COLUMN as DB_COLUMN;

pub struct PoWChainStore<T>
    where T: ClientDB
{
    db: Arc<T>,
}

impl<T: ClientDB> PoWChainStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self {
            db,
        }
    }

    pub fn put_block_hash(&self, hash: &[u8])
        -> Result<(), DBError>
    {
        self.db.put(DB_COLUMN, hash, &vec![0])
    }

    pub fn block_hash_exists(&self, hash: &[u8])
        -> Result<bool, DBError>
    {
        self.db.exists(DB_COLUMN, hash)
    }
}

// TODO: add tests once a memory-db is implemented
