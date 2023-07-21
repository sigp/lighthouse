#![cfg(feature = "redb")]
use std::{
    borrow::{Borrow, Cow},
    marker::PhantomData,
    path::PathBuf,
};

use crate::{
    config::MEGABYTE,
    database::{
        interface::{Key, OpenDatabases, Value},
        *,
    },
    Config, Error,
};

#[derive(Debug)]
pub struct Database<'env> {
    table: &'env str,
    _phantom: PhantomData<&'env ()>,
}

#[derive(Debug)]
pub struct Environment {
    env: PathBuf,
}

impl Environment {
    pub fn new(config: &Config) -> Result<Environment, Error> {
        let env = config.database_path.clone();
        Ok(Environment { env })
    }

    pub fn create_databases(&self) -> Result<OpenDatabases, Error> {
        let indexed_attestation_db = self.create_table(INDEXED_ATTESTATION_DB);
        let indexed_attestation_id_db = self.create_table(INDEXED_ATTESTATION_ID_DB);
        let attesters_db = self.create_table(ATTESTERS_DB);
        let attesters_max_targets_db = self.create_table(ATTESTERS_MAX_TARGETS_DB);
        let min_targets_db = self.create_table(MIN_TARGETS_DB);
        let max_targets_db = self.create_table(MAX_TARGETS_DB);
        let current_epochs_db = self.create_table(CURRENT_EPOCHS_DB);
        let proposers_db = self.create_table(PROPOSERS_DB);
        let metadata_db = self.create_table(METADATA_DB);

        let wrap = |db| {
            crate::Database::Redb(Database {
                table,
                _phantom: PhantomData,
            })
        };

        Ok(OpenDatabases {
            indexed_attestation_db: wrap(indexed_attestation_db),
            indexed_attestation_id_db: indexed_attestation_id_db,
            attesters_db: attesters_db,
            attesters_max_targets_db: attesters_max_targets_db,
            min_targets_db: min_targets_db,
            max_targets_db: max_targets_db,
            current_epochs_db: current_epochs_db,
            proposers_db: proposers_db,
            metadata_db: metadata_db,
        })
    }

    pub fn create_table<'env>(&self, table_name: &'env str) -> Database<'env> {
        Database {
            table: table_name,
            _phantom: PhantomData,
        }
    }

    pub fn begin_rw_txn(&self) -> Result<RwTransaction, Error> {
        Ok(RwTransaction {
            txn: PhantomData,
            _phantom: PhantomData,
        })
    }
}