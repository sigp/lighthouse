#![cfg(feature = "redb")]

use std::marker::PhantomData;
use crate::config::{Config};

pub struct Builder {
    builder: redb::Builder,
}

#[derive(Debug)]
pub struct Database<'db> {
    db: redb::Database,
    _phantom: PhantomData<&'db ()>
}

pub struct WriteTransaction<'db> {
    txn: redb::WriteTransaction<'db>,
}

pub struct Table<'db, 'txn, K: redb::RedbKey + 'static, V: redb::RedbValue + 'static> {
    table: redb::Table<'db, 'txn, K, V>
}

impl Builder {
    pub fn new(config: &Config) -> Builder {
        let builder = redb::Builder::new();

        Builder{ builder }
    }
}