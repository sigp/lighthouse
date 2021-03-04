use crate::{DBColumn, Error, StoreItem};
use ssz::{Decode, Encode};
use types::{Checkpoint, Hash256};

pub const CURRENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion(3);

// All the keys that get stored under the `BeaconMeta` column.
//
// We use `repeat_byte` because it's a const fn.
pub const SCHEMA_VERSION_KEY: Hash256 = Hash256::repeat_byte(0);
pub const CONFIG_KEY: Hash256 = Hash256::repeat_byte(1);
pub const SPLIT_KEY: Hash256 = Hash256::repeat_byte(2);
pub const PRUNING_CHECKPOINT_KEY: Hash256 = Hash256::repeat_byte(3);
pub const COMPACTION_TIMESTAMP_KEY: Hash256 = Hash256::repeat_byte(4);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaVersion(pub u64);

impl SchemaVersion {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl StoreItem for SchemaVersion {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(SchemaVersion(u64::from_ssz_bytes(bytes)?))
    }
}

/// The checkpoint used for pruning the database.
///
/// Updated whenever pruning is successful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruningCheckpoint {
    pub checkpoint: Checkpoint,
}

impl StoreItem for PruningCheckpoint {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.checkpoint.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(PruningCheckpoint {
            checkpoint: Checkpoint::from_ssz_bytes(bytes)?,
        })
    }
}

/// The last time the database was compacted.
pub struct CompactionTimestamp(pub u64);

impl StoreItem for CompactionTimestamp {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.0.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(CompactionTimestamp(u64::from_ssz_bytes(bytes)?))
    }
}
