macro_rules! impl_crud_for_store {
    ($store: ident, $db_column: expr) => {
        impl<T: ClientDB> $store<T> {
            pub fn put(&self, hash: &Hash256, ssz: &[u8]) -> Result<(), DBError> {
                self.db.put($db_column, hash.as_bytes(), ssz)
            }

            pub fn get(&self, hash: &Hash256) -> Result<Option<Vec<u8>>, DBError> {
                self.db.get($db_column, hash.as_bytes())
            }

            pub fn exists(&self, hash: &Hash256) -> Result<bool, DBError> {
                self.db.exists($db_column, hash.as_bytes())
            }

            pub fn delete(&self, hash: &Hash256) -> Result<(), DBError> {
                self.db.delete($db_column, hash.as_bytes())
            }
        }
    };
}

#[cfg(test)]
macro_rules! test_crud_for_store {
    ($store: ident, $db_column: expr) => {
        #[test]
        fn test_put() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);

            store.put(hash, ssz).unwrap();
            assert_eq!(db.get(DB_COLUMN, hash.as_bytes()).unwrap().unwrap(), ssz);
        }

        #[test]
        fn test_get() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);

            db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
            assert_eq!(store.get(hash).unwrap().unwrap(), ssz);
        }

        #[test]
        fn test_get_unknown() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);
            let other_hash = &Hash256::from([0xBB; 32]);

            db.put(DB_COLUMN, other_hash.as_bytes(), ssz).unwrap();
            assert_eq!(store.get(hash).unwrap(), None);
        }

        #[test]
        fn test_exists() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);

            db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
            assert!(store.exists(hash).unwrap());
        }

        #[test]
        fn test_block_does_not_exist() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);
            let other_hash = &Hash256::from([0xBB; 32]);

            db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
            assert!(!store.exists(other_hash).unwrap());
        }

        #[test]
        fn test_delete() {
            let db = Arc::new(MemoryDB::open());
            let store = $store::new(db.clone());

            let ssz = "some bytes".as_bytes();
            let hash = &Hash256::from([0xAA; 32]);

            db.put(DB_COLUMN, hash.as_bytes(), ssz).unwrap();
            assert!(db.exists(DB_COLUMN, hash.as_bytes()).unwrap());

            store.delete(hash).unwrap();
            assert!(!db.exists(DB_COLUMN, hash.as_bytes()).unwrap());
        }
    };
}
