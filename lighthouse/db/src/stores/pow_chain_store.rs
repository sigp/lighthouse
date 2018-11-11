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
        self.db.put(DB_COLUMN, hash, &[0])
    }

    pub fn block_hash_exists(&self, hash: &[u8])
        -> Result<bool, DBError>
    {
        self.db.exists(DB_COLUMN, hash)
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;
    
    use super::*;
    use super::super::super::MemoryDB;

    #[test]
    fn test_put_block_hash() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash: &[u8] = &[rand::random()];
        store.put_block_hash(hash);

        assert!(db.exists(DB_COLUMN, hash).unwrap());
    }

    #[test]
    fn test_block_hash_exists() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash: &[u8] = &[rand::random()];
        db.put(DB_COLUMN, hash, &[0]);

        assert!(store.block_hash_exists(hash).unwrap());
    }

    #[test]
    fn test_block_hash_does_not_exist() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash: &[u8] = &[rand::random()];
        let other_hash: &[u8] = &[rand::random()];
        db.put(DB_COLUMN, hash, &[0]);

        assert!(!store.block_hash_exists(other_hash).unwrap());
    }
}
