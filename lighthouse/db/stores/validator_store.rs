use std::sync::Arc;
use super::{
    ClientDB,
    DBError,
};
use super::VALIDATOR_DB_COLUMN as DB_COLUMN;

pub struct ValidatorStore<T>
    where T: ClientDB
{
    db: Arc<T>,
}

impl<T: ClientDB> ValidatorStore<T> {
    pub fn new(db: Arc<T>) -> Self {
        Self {
            db,
        }
    }

    pub fn put_validator_record_by_index(&self, hash: &[u8], val: &[u8])
        -> Result<(), DBError>
    {
        self.db.put(DB_COLUMN, hash, val)
    }

    pub fn get_validator_record_by_index(&self, hash: &[u8])
        -> Result<bool, DBError>
    {
        self.db.exists(DB_COLUMN, hash)
    }
}

// TODO: add tests
