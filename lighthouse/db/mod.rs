extern crate rocksdb;

mod disk_db;

pub use self::disk_db::DiskDB;

#[derive(Debug)]
pub struct DBError {
    message: String
}

impl DBError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

pub trait ClientDB: Sync + Send {
    fn get(&self, col: &str, key: &[u8])
        -> Result<Option<&[u8]>, DBError>;
}
