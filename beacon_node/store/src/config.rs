use crate::{DBColumn, Error, StoreItem};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::{EthSpec, MinimalEthSpec};

pub const PREV_DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 2048;
pub const DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 8192;
pub const DEFAULT_EPOCHS_PER_STATE_DIFF: u64 = 4;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 64;
pub const DEFAULT_STATE_CACHE_SIZE: usize = 128;
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
const EST_COMPRESSION_FACTOR: usize = 2;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Number of slots to wait between storing restore points in the freezer database.
    pub slots_per_restore_point: u64,
    /// Flag indicating whether the `slots_per_restore_point` was set explicitly by the user.
    pub slots_per_restore_point_set_explicitly: bool,
    /// Number of epochs between state diffs in the hot database.
    pub epochs_per_state_diff: u64,
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: usize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: usize,
    /// Compression level for `BeaconStateDiff`s.
    pub compression_level: i32,
    /// Whether to compact the database on initialization.
    pub compact_on_init: bool,
    /// Whether to compact the database during database pruning.
    pub compact_on_prune: bool,
    /// Whether to prune payloads on initialization and finalization.
    pub prune_payloads: bool,
    /// Whether to store finalized blocks compressed and linearised in the freezer database.
    pub linear_blocks: bool,
    /// Whether to store finalized states compressed and linearised in the freezer database.
    pub linear_restore_points: bool,
}

/// Variant of `StoreConfig` that gets written to disk. Contains immutable configuration params.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
// FIXME(sproul): schema migration
pub struct OnDiskStoreConfig {
    pub slots_per_restore_point: u64,
    pub linear_blocks: bool,
    pub linear_restore_points: bool,
}

#[derive(Debug, Clone)]
pub enum StoreConfigError {
    MismatchedSlotsPerRestorePoint { config: u64, on_disk: u64 },
    InvalidCompressionLevel { level: i32 },
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            // Safe default for tests, shouldn't ever be read by a CLI node.
            slots_per_restore_point: MinimalEthSpec::slots_per_historical_root() as u64,
            slots_per_restore_point_set_explicitly: false,
            epochs_per_state_diff: DEFAULT_EPOCHS_PER_STATE_DIFF,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            state_cache_size: DEFAULT_STATE_CACHE_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            linear_blocks: true,
            linear_restore_points: true,
        }
    }
}

impl StoreConfig {
    pub fn as_disk_config(&self) -> OnDiskStoreConfig {
        OnDiskStoreConfig {
            slots_per_restore_point: self.slots_per_restore_point,
            linear_blocks: self.linear_blocks,
            linear_restore_points: self.linear_restore_points,
        }
    }

    pub fn check_compatibility(
        &self,
        on_disk_config: &OnDiskStoreConfig,
    ) -> Result<(), StoreConfigError> {
        if self.slots_per_restore_point != on_disk_config.slots_per_restore_point {
            return Err(StoreConfigError::MismatchedSlotsPerRestorePoint {
                config: self.slots_per_restore_point,
                on_disk: on_disk_config.slots_per_restore_point,
            });
        }
        Ok(())
    }

    /// Check that the compression level is valid.
    pub fn verify_compression_level(&self) -> Result<(), StoreConfigError> {
        if zstd::compression_level_range().contains(&self.compression_level) {
            Ok(())
        } else {
            Err(StoreConfigError::InvalidCompressionLevel {
                level: self.compression_level,
            })
        }
    }

    /// Estimate the size of `len` bytes after compression at the current compression level.
    pub fn estimate_compressed_size(&self, len: usize) -> usize {
        if self.compression_level == 0 {
            len
        } else {
            len / EST_COMPRESSION_FACTOR
        }
    }

    /// Estimate the size of `len` compressed bytes after decompression at the current compression
    /// level.
    pub fn estimate_decompressed_size(&self, len: usize) -> usize {
        if self.compression_level == 0 {
            len
        } else {
            len * EST_COMPRESSION_FACTOR
        }
    }
}

impl StoreItem for OnDiskStoreConfig {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}
