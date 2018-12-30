use super::STATES_DB_COLUMN as DB_COLUMN;
use super::{ClientDB, DBError};
use ssz::Decodable;
use std::sync::Arc;
use types::{readers::BeaconStateReader, BeaconState, Hash256};

pub struct BeaconStateStore<T>
where
    T: ClientDB,
{
    db: Arc<T>,
}

impl<T: ClientDB> BeaconStateStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self { db }
    }

    pub fn put(&self, hash: &Hash256, ssz: &[u8]) -> Result<(), DBError> {
        self.db.put(DB_COLUMN, hash, ssz)
    }

    pub fn get(&self, hash: &[u8]) -> Result<Option<Vec<u8>>, DBError> {
        self.db.get(DB_COLUMN, hash)
    }

    pub fn exists(&self, hash: &[u8]) -> Result<bool, DBError> {
        self.db.exists(DB_COLUMN, hash)
    }

    pub fn delete(&self, hash: &[u8]) -> Result<(), DBError> {
        self.db.delete(DB_COLUMN, hash)
    }

    /// Retuns a fully de-serialized `BeaconState` (or `None` if hash not known).
    pub fn get_deserialized(&self, hash: &[u8]) -> Result<Option<impl BeaconStateReader>, DBError> {
        match self.get(&hash)? {
            None => Ok(None),
            Some(ssz) => {
                let (state, _) = BeaconState::ssz_decode(&ssz, 0).map_err(|_| DBError {
                    message: "Bad State SSZ.".to_string(),
                })?;
                Ok(Some(state))
            }
        }
    }
}
