#![cfg(feature = "redb")]

use redb::TableDefinition;

use crate::config::Config;
use crate::database::{interface::OpenDatabases, *};
use crate::Error;
use std::marker::PhantomData;
use std::path::PathBuf;

pub struct Builder {
    builder: redb::Builder,
}

#[derive(Debug)]
pub struct Database<'db> {
    db: redb::Database,
    _phantom: PhantomData<&'db ()>,
}

pub struct WriteTransaction<'db> {
    txn: redb::WriteTransaction<'db>,
}

pub struct Table<'db, 'txn, K: redb::RedbKey + 'static, V: redb::RedbValue + 'static> {
    table: redb::Table<'db, 'txn, K, V>,
}

impl Builder {
    pub fn new(config: &Config) -> Builder {
        let builder = redb::Builder::new();

        Builder { builder }
    }
}

pub struct Environment {
    builder: redb::Builder,
    dbi_open_mutex: Mutex<i32>,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let builder = redb::Builder::new();
        let mutex = Mutex::new(0);
        Ok(Environment {
            builder,
            dbi_open_mutex: mutex,
        })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let mutex = self.dbi_open_mutex.lock();
        let indexed_attestation_db = self.builder.create(INDEXED_ATTESTATION_DB).unwrap();
        let indexed_attestation_id_db = self.builder.create(INDEXED_ATTESTATION_ID_DB).unwrap();
        let attesters_db = self.builder.create(ATTESTERS_DB).unwrap();
        let attesters_max_targets_db = self.builder.create(ATTESTERS_MAX_TARGETS_DB).unwrap();
        let min_targets_db = self.builder.create(MIN_TARGETS_DB).unwrap();
        let max_targets_db = self.builder.create(MAX_TARGETS_DB).unwrap();
        let current_epochs_db = self.builder.create(CURRENT_EPOCHS_DB).unwrap();
        let proposers_db = self.builder.create(PROPOSERS_DB).unwrap();
        let metadata_db = self.builder.create(METADATA_DB).unwrap();

        let wrap = |db| {
            crate::Database::Redb(Database {
                db,
                _phantom: PhantomData,
            })
        };

        drop(mutex);

        Ok(OpenDatabases {
            indexed_attestation_db: wrap(indexed_attestation_db),
            indexed_attestation_id_db: wrap(indexed_attestation_id_db),
            attesters_db: wrap(attesters_db),
            attesters_max_targets_db: wrap(attesters_max_targets_db),
            min_targets_db: wrap(min_targets_db),
            max_targets_db: wrap(max_targets_db),
            current_epochs_db: wrap(current_epochs_db),
            proposers_db: wrap(proposers_db),
            metadata_db: wrap(metadata_db),
        })
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        todo!()
    }

    pub fn filenames(&self, config: &Config) -> Vec<PathBuf> {
        vec![
            config.database_path.join("data.mdb"),
            config.database_path.join("lock.mdb"),
        ]
    }
}
