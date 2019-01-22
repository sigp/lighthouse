use super::POW_CHAIN_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use std::sync::Arc;

pub struct PoWChainStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

impl<T: ClientDB> PoWChainStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    pub fn put_block_hash(&self, hash: &[u8]) -> Result<(), DBError> {
        self.db.put(DB_COLUMN, hash, &[0])
    }

    pub fn block_hash_exists(&self, hash: &[u8]) -> Result<bool, DBError> {
        self.db.exists(DB_COLUMN, hash)
    }
}

#[cfg(test)]
mod tests {
    extern crate types;

    use super::super::super::MemoryDB;
    use super::*;

    use self::types::Hash256;

    #[test]
    fn test_put_block_hash() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        store.put_block_hash(hash).unwrap();

        assert!(db.exists(DB_COLUMN, hash).unwrap());
    }

    #[test]
    fn test_block_hash_exists() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        db.put(DB_COLUMN, hash, &[0]).unwrap();

        assert!(store.block_hash_exists(hash).unwrap());
    }

    #[test]
    fn test_block_hash_does_not_exist() {
        let db = Arc::new(MemoryDB::open());
        let store = PoWChainStore::new(db.clone());

        let hash = &Hash256::from("some hash".as_bytes()).to_vec();
        let other_hash = &Hash256::from("another hash".as_bytes()).to_vec();
        db.put(DB_COLUMN, hash, &[0]).unwrap();

        assert!(!store.block_hash_exists(other_hash).unwrap());
    }
}
