use crate::hdiff::HierarchyConfig;
use crate::{DBColumn, Error, StoreItem};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::Write;
use zstd::Encoder;

pub const DEFAULT_EPOCHS_PER_STATE_DIFF: u64 = 4;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 64;
pub const DEFAULT_STATE_CACHE_SIZE: usize = 128;
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
const EST_COMPRESSION_FACTOR: usize = 2;
pub const DEFAULT_HISTORIC_STATE_CACHE_SIZE: usize = 1;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Number of epochs between state diffs in the hot database.
    pub epochs_per_state_diff: u64,
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: usize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: usize,
    /// Compression level for `BeaconStateDiff`s.
    pub compression_level: i32,
    /// Maximum number of states from freezer database to store in the in-memory state cache.
    pub historic_state_cache_size: usize,
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
    /// State diff hierarchy.
    pub hierarchy_config: HierarchyConfig,
}

/// Variant of `StoreConfig` that gets written to disk. Contains immutable configuration params.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
// FIXME(sproul): schema migration, add hdiff
pub struct OnDiskStoreConfig {
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
            epochs_per_state_diff: DEFAULT_EPOCHS_PER_STATE_DIFF,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            state_cache_size: DEFAULT_STATE_CACHE_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            historic_state_cache_size: DEFAULT_HISTORIC_STATE_CACHE_SIZE,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            linear_blocks: true,
            linear_restore_points: true,
            hierarchy_config: HierarchyConfig::default(),
        }
    }
}

impl StoreConfig {
    pub fn as_disk_config(&self) -> OnDiskStoreConfig {
        OnDiskStoreConfig {
            linear_blocks: self.linear_blocks,
            linear_restore_points: self.linear_restore_points,
        }
    }

    pub fn check_compatibility(
        &self,
        _on_disk_config: &OnDiskStoreConfig,
    ) -> Result<(), StoreConfigError> {
        // FIXME(sproul): TODO
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

    pub fn compress_bytes(&self, ssz_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let mut compressed_value =
            Vec::with_capacity(self.estimate_compressed_size(ssz_bytes.len()));
        let mut encoder = Encoder::new(&mut compressed_value, self.compression_level)
            .map_err(Error::Compression)?;
        encoder.write_all(ssz_bytes).map_err(Error::Compression)?;
        encoder.finish().map_err(Error::Compression)?;
        Ok(compressed_value)
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
