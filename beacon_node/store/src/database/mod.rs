use crate::StoreError as Error;
use crate::{DBColumn, KeyValueStore};
use leveldb::database::Database;
use leveldb::iterator::LevelDBIterator;
use leveldb::options::{Options, ReadOptions, WriteOptions};
use std::path::Path;
use std::sync::Arc;
use types::EthSpec;

pub mod config;
pub mod interface;

pub use interface::BeaconNodeBackend;

pub struct LevelDB<E: EthSpec> {
    db: Arc<Database>,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: EthSpec> LevelDB<E> {
    pub fn open(path: &Path) -> Result<Self, Error> {
        let mut options = Options::new();
        options.create_if_missing = true;
        
        let db = Database::open(path, options)
            .map_err(|e| Error::DBError(format!("Failed to open database: {:?}", e)))?;
            
        Ok(Self {
            db: Arc::new(db),
            _phantom: std::marker::PhantomData,
        })
    }
    
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let read_opts = ReadOptions::new();
        self.db
            .get(read_opts, key)
            .map_err(|e| Error::DBError(format!("DB read error: {:?}", e)))
    }
    
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let write_opts = WriteOptions::new();
        self.db
            .put(write_opts, key, value)
            .map_err(|e| Error::DBError(format!("DB write error: {:?}", e)))
    }
    
    pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
        let write_opts = WriteOptions::new();
        self.db
            .delete(write_opts, key)
            .map_err(|e| Error::DBError(format!("DB delete error: {:?}", e)))
    }
    
    pub fn iter(&self) -> impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), Error>> + '_ {
        let read_opts = ReadOptions::new();
        let iter = self.db.iter(read_opts);
        
        iter.map(|result| {
            result.map_err(|e| Error::DBError(format!("DB iteration error: {:?}", e)))
        })
    }
} 