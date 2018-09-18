extern crate rocksdb;

mod disk_db;

pub use self::disk_db::DiskDB;

type DBValue = Vec<u8>;

#[derive(Debug)]
pub struct DBError {
    message: String
}

impl DBError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

pub trait ClientDB: Sync + Send {
    fn get(&self, col: &str, key: &[u8])
        -> Result<Option<DBValue>, DBError>;

    fn put(&self, col: &str, key: &[u8], val: &[u8])
        -> Result<(), DBError>;
}
