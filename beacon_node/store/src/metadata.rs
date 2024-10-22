use crate::{DBColumn, Error, StoreItem};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::{Checkpoint, Hash256, Slot};

pub const CURRENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion(22);

// All the keys that get stored under the `BeaconMeta` column.
//
// We use `repeat_byte` because it's a const fn.
pub const SCHEMA_VERSION_KEY: Hash256 = Hash256::repeat_byte(0);
pub const CONFIG_KEY: Hash256 = Hash256::repeat_byte(1);
pub const SPLIT_KEY: Hash256 = Hash256::repeat_byte(2);
pub const PRUNING_CHECKPOINT_KEY: Hash256 = Hash256::repeat_byte(3);
pub const COMPACTION_TIMESTAMP_KEY: Hash256 = Hash256::repeat_byte(4);
pub const ANCHOR_INFO_KEY: Hash256 = Hash256::repeat_byte(5);
pub const BLOB_INFO_KEY: Hash256 = Hash256::repeat_byte(6);
pub const DATA_COLUMN_INFO_KEY: Hash256 = Hash256::repeat_byte(7);

/// State upper limit value used to indicate that a node is not storing historic states.
pub const STATE_UPPER_LIMIT_NO_RETAIN: Slot = Slot::new(u64::MAX);

/// The `AnchorInfo` encoding full availability of all historic blocks & states.
pub const ANCHOR_FOR_ARCHIVE_NODE: AnchorInfo = AnchorInfo {
    anchor_slot: Slot::new(0),
    oldest_block_slot: Slot::new(0),
    oldest_block_parent: Hash256::ZERO,
    state_upper_limit: Slot::new(0),
    state_lower_limit: Slot::new(0),
};

/// The `AnchorInfo` encoding an uninitialized anchor.
///
/// This value should never exist except on initial start-up prior to the anchor being initialised
/// by `init_anchor_info`.
pub const ANCHOR_UNINITIALIZED: AnchorInfo = AnchorInfo {
    anchor_slot: Slot::new(u64::MAX),
    oldest_block_slot: Slot::new(u64::MAX),
    oldest_block_parent: Hash256::ZERO,
    state_upper_limit: Slot::new(u64::MAX),
    state_lower_limit: Slot::new(0),
};

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

/// Database parameters relevant to weak subjectivity sync.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct AnchorInfo {
    /// The slot at which the anchor state is present and which we cannot revert. Values on start:
    /// - Genesis start: 0
    /// - Checkpoint sync: Slot of the finalized checkpoint block
    ///
    /// Immutable
    pub anchor_slot: Slot,
    /// All blocks with slots greater than or equal to this value are available in the database.
    /// Additionally, the genesis block is always available.
    ///
    /// Values on start:
    /// - Genesis start: 0
    /// - Checkpoint sync: Slot of the finalized checkpoint block
    ///
    /// Progressively decreases during backfill sync until reaching 0.
    pub oldest_block_slot: Slot,
    /// The block root of the next block that needs to be added to fill in the history.
    ///
    /// Zero if we know all blocks back to genesis.
    pub oldest_block_parent: Hash256,
    /// All states with slots _greater than or equal to_ `min(split.slot, state_upper_limit)` are
    /// available in the database. If `state_upper_limit` is higher than `split.slot`, states are
    /// not being written to the freezer database.
    ///
    /// Values on start if state reconstruction is enabled:
    /// - Genesis start: 0
    /// - Checkpoint sync: Slot of the next scheduled snapshot
    ///
    /// Value on start if state reconstruction is disabled:
    /// - 2^64 - 1 representing no historic state storage.
    ///
    /// Immutable until state reconstruction completes.
    pub state_upper_limit: Slot,
    /// All states with slots _less than or equal to_ this value are available in the database.
    /// The minimum value is 0, indicating that the genesis state is always available.
    ///
    /// Values on start:
    /// - Genesis start: 0
    /// - Checkpoint sync: 0
    ///
    /// When full block backfill completes (`oldest_block_slot == 0`) state reconstruction starts and
    /// this value will progressively increase until reaching `state_upper_limit`.
    pub state_lower_limit: Slot,
}

impl AnchorInfo {
    /// Returns true if the block backfill has completed.
    /// This is a comparison between the oldest block slot and the target backfill slot (which is
    /// likely to be the closest WSP).
    pub fn block_backfill_complete(&self, target_slot: Slot) -> bool {
        self.oldest_block_slot <= target_slot
    }

    /// Return true if all historic states are stored, i.e. if state reconstruction is complete.
    pub fn all_historic_states_stored(&self) -> bool {
        self.state_lower_limit == self.state_upper_limit
    }

    /// Return true if no historic states other than genesis are stored in the database.
    pub fn no_historic_states_stored(&self, split_slot: Slot) -> bool {
        self.state_lower_limit == 0 && self.state_upper_limit >= split_slot
    }

    /// Return true if no historic states other than genesis *will ever be stored*.
    pub fn full_state_pruning_enabled(&self) -> bool {
        self.state_lower_limit == 0 && self.state_upper_limit == STATE_UPPER_LIMIT_NO_RETAIN
    }
}

impl StoreItem for AnchorInfo {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Database parameters relevant to blob sync.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, Serialize, Deserialize, Default)]
pub struct BlobInfo {
    /// The slot after which blobs are or *will be* available (>=).
    ///
    /// If this slot is in the future, then it is the first slot of the Deneb fork, from which blobs
    /// will be available.
    ///
    /// If the `oldest_blob_slot` is `None` then this means that the Deneb fork epoch is not yet
    /// known.
    pub oldest_blob_slot: Option<Slot>,
    /// A separate blobs database is in use (deprecated, always `true`).
    pub blobs_db: bool,
}

impl StoreItem for BlobInfo {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// Database parameters relevant to data column sync.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode, Serialize, Deserialize, Default)]
pub struct DataColumnInfo {
    /// The slot after which data columns are or *will be* available (>=).
    ///
    /// If this slot is in the future, then it is the first slot of the EIP-7594 fork, from which
    /// data columns will be available.
    ///
    /// If the `oldest_data_column_slot` is `None` then this means that the EIP-7594 fork epoch is
    /// not yet known.
    pub oldest_data_column_slot: Option<Slot>,
}

impl StoreItem for DataColumnInfo {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
