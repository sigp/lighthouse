extern crate blake2_rfc as blake2;
extern crate bls;
extern crate rocksdb;

mod disk_db;
mod memory_db;
pub mod stores;
mod traits;

use self::stores::COLUMNS;

pub use self::disk_db::DiskDB;
pub use self::memory_db::MemoryDB;
pub use self::traits::{ClientDB, DBError, DBValue};

/// Currently available database options
#[derive(Debug, Clone)]
pub enum DBType {
    Memory,
    RocksDB,
}
