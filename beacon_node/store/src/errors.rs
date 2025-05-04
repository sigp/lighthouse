use crate::chunked_vector::ChunkError;
use crate::config::StoreConfigError;
use crate::hot_cold_store::HotColdDBError;
use crate::{hdiff, DBColumn};
#[cfg(feature = "leveldb")]
use leveldb::error::Error as LevelDBError;
use ssz::DecodeError;
use state_processing::BlockReplayError;
use types::{milhouse, BeaconStateError, EpochCacheError, Hash256, InconsistentFork, Slot};
use crate::StoreError as Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    SszDecodeError(DecodeError),
    VectorChunkError(ChunkError),
    BeaconStateError(BeaconStateError),
    PartialBeaconStateError,
    HotColdDBError(HotColdDBError),
    DBError(String),
    RlpError(String),
    BlockNotFound(Hash256),
    NoContinuationData,
    SplitPointModified(Slot, Slot),
    ConfigError(StoreConfigError),
    SchemaMigrationError(String),
    /// The store's `anchor_info` was mutated concurrently, the latest modification wasn't applied.
    AnchorInfoConcurrentMutation,
    /// The store's `blob_info` was mutated concurrently, the latest modification wasn't applied.
    BlobInfoConcurrentMutation,
    /// The store's `data_column_info` was mutated concurrently, the latest modification wasn't applied.
    DataColumnInfoConcurrentMutation,
    /// The block or state is unavailable due to weak subjectivity sync.
    HistoryUnavailable,
    /// State reconstruction cannot commence because not all historic blocks are known.
    MissingHistoricBlocks {
        start_slot: Slot,
        end_slot: Slot,
    },
    /// State reconstruction failed because it didn't reach the upper limit slot.
    ///
    /// This should never happen (it's a logic error).
    StateReconstructionLogicError,
    StateReconstructionRootMismatch {
        expected: Hash256,
        found: Hash256,
    },
    MissingGenesisState,
    MissingSnapshot(Slot),
    BlockReplayError(BlockReplayError),
    AddPayloadLogicError,
    InvalidKey,
    InvalidBytes,
    InconsistentFork(InconsistentFork),
    #[cfg(feature = "leveldb")]
    LevelDbError(LevelDBError),
    #[cfg(feature = "redb")]
    RedbError(redb::Error),
    CacheBuildError(EpochCacheError),
    RandaoMixOutOfBounds,
    MilhouseError(milhouse::Error),
    Compression(std::io::Error),
    FinalizedStateDecreasingSlot,
    FinalizedStateUnaligned,
    StateForCacheHasPendingUpdates {
        slot: Slot,
    },
    Hdiff(hdiff::Error),
    ForwardsIterInvalidColumn(DBColumn),
    ForwardsIterGap(DBColumn, Slot, Slot),
    StateShouldNotBeRequired(Slot),
    MissingBlock(Hash256),
    GenesisStateUnknown,
    ArithError(safe_arith::ArithError),
    StoreError(String),
    QueueFull,
    BackgroundThreadError,
}

pub trait HandleUnavailable<T> {
    fn handle_unavailable(self) -> std::result::Result<Option<T>, Error>;
}

impl<T> HandleUnavailable<T> for Result<T> {
    fn handle_unavailable(self) -> std::result::Result<Option<T>, Error> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(Error::HistoryUnavailable) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::SszDecodeError(e)
    }
}

impl From<ChunkError> for Error {
    fn from(e: ChunkError) -> Error {
        Error::VectorChunkError(e)
    }
}

impl From<HotColdDBError> for Error {
    fn from(e: HotColdDBError) -> Error {
        Error::HotColdDBError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<StoreConfigError> for Error {
    fn from(e: StoreConfigError) -> Error {
        Error::ConfigError(e)
    }
}

impl From<milhouse::Error> for Error {
    fn from(e: milhouse::Error) -> Self {
        Self::MilhouseError(e)
    }
}

impl From<hdiff::Error> for Error {
    fn from(e: hdiff::Error) -> Self {
        Self::Hdiff(e)
    }
}

impl From<BlockReplayError> for Error {
    fn from(e: BlockReplayError) -> Error {
        Error::BlockReplayError(e)
    }
}

impl From<InconsistentFork> for Error {
    fn from(e: InconsistentFork) -> Error {
        Error::InconsistentFork(e)
    }
}

#[cfg(feature = "leveldb")]
impl From<LevelDBError> for Error {
    fn from(e: LevelDBError) -> Error {
        Error::LevelDbError(e)
    }
}

#[cfg(feature = "redb")]
impl From<redb::Error> for Error {
    fn from(e: redb::Error) -> Self {
        Error::RedbError(e)
    }
}

#[cfg(feature = "redb")]
impl From<redb::TableError> for Error {
    fn from(e: redb::TableError) -> Self {
        Error::RedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::TransactionError> for Error {
    fn from(e: redb::TransactionError) -> Self {
        Error::RedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::DatabaseError> for Error {
    fn from(e: redb::DatabaseError) -> Self {
        Error::RedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::StorageError> for Error {
    fn from(e: redb::StorageError) -> Self {
        Error::RedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::CommitError> for Error {
    fn from(e: redb::CommitError) -> Self {
        Error::RedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::CompactionError> for Error {
    fn from(e: redb::CompactionError) -> Self {
        Error::RedbError(e.into())
    }
}

impl From<EpochCacheError> for Error {
    fn from(e: EpochCacheError) -> Error {
        Error::CacheBuildError(e)
    }
}

impl From<safe_arith::ArithError> for Error {
    fn from(e: safe_arith::ArithError) -> Error {
        Error::ArithError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DBError(s) => write!(f, "Database error: {}", s),
            Error::InvalidKey => write!(f, "Invalid key"),
            Error::BlockNotFound(hash) => write!(f, "Block not found: {}", hash),
            Error::HistoryUnavailable => write!(f, "History unavailable"),
            Error::SplitPointModified(a, b) => write!(f, "Split point modified: {} -> {}", a, b),
            Error::StateReconstructionLogicError => write!(f, "State reconstruction logic error"),
            Error::StateReconstructionRootMismatch { expected, found } => {
                write!(f, "State reconstruction root mismatch: expected {}, found {}", expected, found)
            }
            Error::FinalizedStateUnaligned => write!(f, "Finalized state unaligned"),
            Error::FinalizedStateDecreasingSlot => write!(f, "Finalized state decreasing slot"),
            Error::StateForCacheHasPendingUpdates { slot } => {
                write!(f, "State for cache has pending updates at slot {}", slot)
            }
            Error::RandaoMixOutOfBounds => write!(f, "Randao mix out of bounds"),
            Error::PartialBeaconStateError => write!(f, "Partial beacon state error"),
            Error::MissingHistoricBlocks { start_slot, end_slot } => {
                write!(f, "Missing historic blocks from slot {} to {}", start_slot, end_slot)
            }
            Error::StateShouldNotBeRequired(slot) => {
                write!(f, "State should not be required at slot {}", slot)
            }
            Error::BeaconStateError(e) => write!(f, "Beacon state error: {:?}", e),
            Error::HotColdDBError(s) => write!(f, "Hot/cold DB error: {}", s),
            Error::Hdiff(e) => write!(f, "HDiff error: {:?}", e),
            Error::StoreError(s) => write!(f, "Store error: {}", s),
            Error::QueueFull => write!(f, "Queue full"),
            Error::BackgroundThreadError => write!(f, "Background thread error"),
        }
    }
}

impl std::error::Error for Error {}
