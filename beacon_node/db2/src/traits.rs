pub type DBValue = Vec<u8>;

#[derive(Debug)]
pub struct DBError {
    pub message: String,
}

impl DBError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

/// A generic database to be used by the "client' (i.e.,
/// the lighthouse blockchain client).
///
/// The purpose of having this generic trait is to allow the
/// program to use a persistent on-disk database during production,
/// but use a transient database during tests.
pub trait ClientDB: Sync + Send {
    fn get(&self, col: &str, key: &[u8]) -> Result<Option<DBValue>, DBError>;

    fn put(&self, col: &str, key: &[u8], val: &[u8]) -> Result<(), DBError>;

    fn exists(&self, col: &str, key: &[u8]) -> Result<bool, DBError>;

    fn delete(&self, col: &str, key: &[u8]) -> Result<(), DBError>;
}

pub enum DBColumn {
    Block,
    State,
    BeaconChain,
}

pub trait DBStore {
    fn db_column(&self) -> DBColumn;
}
