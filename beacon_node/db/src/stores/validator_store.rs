extern crate bytes;

use self::bytes::{BufMut, BytesMut};
use super::VALIDATOR_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use bls::PublicKey;
use ssz::{Decodable, Encodable};
use std::sync::Arc;

#[derive(Debug, PartialEq)]
pub enum ValidatorStoreError {
    DBError(String),
    DecodeError,
}

impl From<DBError> for ValidatorStoreError {
    fn from(error: DBError) -> Self {
        ValidatorStoreError::DBError(error.message)
    }
}

#[derive(Debug, PartialEq)]
enum KeyPrefixes {
    PublicKey,
}

pub struct ValidatorStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

impl<T: ClientDB> ValidatorStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    fn prefix_bytes(&self, key_prefix: &KeyPrefixes) -> Vec<u8> {
        match key_prefix {
            KeyPrefixes::PublicKey => b"pubkey".to_vec(),
        }
    }

    fn get_db_key_for_index(&self, key_prefix: &KeyPrefixes, index: usize) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(6 + 8);
        buf.put(self.prefix_bytes(key_prefix));
        buf.put_u64_be(index as u64);
        buf.take().to_vec()
    }

    pub fn put_public_key_by_index(
        &self,
        index: usize,
        public_key: &PublicKey,
    ) -> Result<(), ValidatorStoreError> {
        let key = self.get_db_key_for_index(&KeyPrefixes::PublicKey, index);
        let val = public_key.as_ssz_bytes();
        self.db
            .put(DB_COLUMN, &key[..], &val[..])
            .map_err(ValidatorStoreError::from)
    }

    pub fn get_public_key_by_index(
        &self,
        index: usize,
    ) -> Result<Option<PublicKey>, ValidatorStoreError> {
        let key = self.get_db_key_for_index(&KeyPrefixes::PublicKey, index);
        let val = self.db.get(DB_COLUMN, &key[..])?;
        match val {
            None => Ok(None),
            Some(val) => match PublicKey::from_ssz_bytes(&val) {
                Ok(key) => Ok(Some(key)),
                Err(_) => Err(ValidatorStoreError::DecodeError),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::MemoryDB;
    use super::*;
    use bls::Keypair;

    #[test]
    fn test_prefix_bytes() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        assert_eq!(
            store.prefix_bytes(&KeyPrefixes::PublicKey),
            b"pubkey".to_vec()
        );
    }

    #[test]
    fn test_get_db_key_for_index() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        let mut buf = BytesMut::with_capacity(6 + 8);
        buf.put(b"pubkey".to_vec());
        buf.put_u64_be(42);
        assert_eq!(
            store.get_db_key_for_index(&KeyPrefixes::PublicKey, 42),
            buf.take().to_vec()
        )
    }

    #[test]
    fn test_put_public_key_by_index() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        let index = 3;
        let public_key = Keypair::random().pk;

        store.put_public_key_by_index(index, &public_key).unwrap();
        let public_key_at_index = db
            .get(
                DB_COLUMN,
                &store.get_db_key_for_index(&KeyPrefixes::PublicKey, index)[..],
            )
            .unwrap()
            .unwrap();

        assert_eq!(public_key_at_index, public_key.as_ssz_bytes());
    }

    #[test]
    fn test_get_public_key_by_index() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        let index = 4;
        let public_key = Keypair::random().pk;

        db.put(
            DB_COLUMN,
            &store.get_db_key_for_index(&KeyPrefixes::PublicKey, index)[..],
            &public_key.as_ssz_bytes(),
        )
        .unwrap();

        let public_key_at_index = store.get_public_key_by_index(index).unwrap().unwrap();
        assert_eq!(public_key_at_index, public_key);
    }

    #[test]
    fn test_get_public_key_by_unknown_index() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        let public_key = Keypair::random().pk;

        db.put(
            DB_COLUMN,
            &store.get_db_key_for_index(&KeyPrefixes::PublicKey, 3)[..],
            &public_key.as_ssz_bytes(),
        )
        .unwrap();

        let public_key_at_index = store.get_public_key_by_index(4).unwrap();
        assert_eq!(public_key_at_index, None);
    }

    #[test]
    fn test_get_invalid_public_key() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db.clone());

        let key = store.get_db_key_for_index(&KeyPrefixes::PublicKey, 42);
        db.put(DB_COLUMN, &key[..], "cats".as_bytes()).unwrap();

        assert_eq!(
            store.get_public_key_by_index(42),
            Err(ValidatorStoreError::DecodeError)
        );
    }

    #[test]
    fn test_validator_store_put_get() {
        let db = Arc::new(MemoryDB::open());
        let store = ValidatorStore::new(db);

        let keys = vec![
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
            Keypair::random(),
        ];

        for i in 0..keys.len() {
            store.put_public_key_by_index(i, &keys[i].pk).unwrap();
        }

        /*
         * Check all keys are retrieved correctly.
         */
        for i in 0..keys.len() {
            let retrieved = store.get_public_key_by_index(i).unwrap().unwrap();
            assert_eq!(retrieved, keys[i].pk);
        }

        /*
         * Check that an index that wasn't stored returns None.
         */
        assert!(store
            .get_public_key_by_index(keys.len() + 1)
            .unwrap()
            .is_none());
    }
}
