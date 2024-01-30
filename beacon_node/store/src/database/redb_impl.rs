use std::{marker::PhantomData, path::Path, sync::Mutex};
use crate::hot_cold_store::{BytesKey, HotColdDBError};
use types::EthSpec;
use crate::Error;

pub struct Redb<E: EthSpec> {
    db: redb::Database,
    transaction_mutex: Mutex<()>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Redb<E> {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let db = redb::Database::create(path)?;
        let transaction_mutex = Mutex::new(());

        Ok(Self {
            db,
            transaction_mutex,
            _phantom: PhantomData,
        })
    }
}