use crate::hdiff::HierarchyConfig;
use crate::{AnchorInfo, DBColumn, Error, Split, StoreItem};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::Write;
use std::num::NonZeroUsize;
use types::non_zero_usize::new_non_zero_usize;
use types::{EthSpec, Unsigned};
use zstd::Encoder;

// Only used in tests. Mainnet sets a higher default on the CLI.
pub const DEFAULT_EPOCHS_PER_STATE_DIFF: u64 = 8;
pub const DEFAULT_BLOCK_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(64);
pub const DEFAULT_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(128);
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
pub const DEFAULT_DIFF_BUFFER_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(16);
const EST_COMPRESSION_FACTOR: usize = 2;
pub const DEFAULT_HISTORIC_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(1);
pub const DEFAULT_EPOCHS_PER_BLOB_PRUNE: u64 = 1;
pub const DEFAULT_BLOB_PUNE_MARGIN_EPOCHS: u64 = 0;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Number of epochs between state diffs in the hot database.
    pub epochs_per_state_diff: u64,
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: NonZeroUsize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: NonZeroUsize,
    /// Compression level for blocks, state diffs and other compressed values.
    pub compression_level: i32,
    /// Maximum number of `HDiffBuffer`s to store in memory.
    pub diff_buffer_cache_size: NonZeroUsize,
    /// Maximum number of states from freezer database to store in the in-memory state cache.
    pub historic_state_cache_size: NonZeroUsize,
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
    /// Whether to prune blobs older than the blob data availability boundary.
    pub prune_blobs: bool,
    /// Frequency of blob pruning in epochs. Default: 1 (every epoch).
    pub epochs_per_blob_prune: u64,
    /// The margin for blob pruning in epochs. The oldest blobs are pruned up until
    /// data_availability_boundary - blob_prune_margin_epochs. Default: 0.
    pub blob_prune_margin_epochs: u64,
}

/// Variant of `StoreConfig` that gets written to disk. Contains immutable configuration params.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
// FIXME(sproul): schema migration
pub struct OnDiskStoreConfig {
    pub linear_blocks: bool,
    pub hierarchy_config: HierarchyConfig,
}

#[derive(Debug, Clone)]
pub enum StoreConfigError {
    MismatchedSlotsPerRestorePoint {
        config: u64,
        on_disk: u64,
    },
    InvalidCompressionLevel {
        level: i32,
    },
    IncompatibleStoreConfig {
        config: OnDiskStoreConfig,
        on_disk: OnDiskStoreConfig,
    },
    InvalidEpochsPerStateDiff {
        epochs_per_state_diff: u64,
        max_supported: u64,
    },
    ZeroEpochsPerBlobPrune,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            epochs_per_state_diff: DEFAULT_EPOCHS_PER_STATE_DIFF,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            state_cache_size: DEFAULT_STATE_CACHE_SIZE,
            diff_buffer_cache_size: DEFAULT_DIFF_BUFFER_CACHE_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            historic_state_cache_size: DEFAULT_HISTORIC_STATE_CACHE_SIZE,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            linear_blocks: true,
            linear_restore_points: true,
            hierarchy_config: HierarchyConfig::default(),
            prune_blobs: true,
            epochs_per_blob_prune: DEFAULT_EPOCHS_PER_BLOB_PRUNE,
            blob_prune_margin_epochs: DEFAULT_BLOB_PUNE_MARGIN_EPOCHS,
        }
    }
}

impl StoreConfig {
    pub fn as_disk_config(&self) -> OnDiskStoreConfig {
        OnDiskStoreConfig {
            linear_blocks: self.linear_blocks,
            hierarchy_config: self.hierarchy_config.clone(),
        }
    }

    pub fn check_compatibility(
        &self,
        on_disk_config: &OnDiskStoreConfig,
        split: &Split,
        anchor: Option<&AnchorInfo>,
    ) -> Result<(), StoreConfigError> {
        let db_config = self.as_disk_config();
        // Allow changing the hierarchy exponents if no historic states are stored.
        if db_config.linear_blocks == on_disk_config.linear_blocks
            && (db_config.hierarchy_config == on_disk_config.hierarchy_config
                || anchor.map_or(false, |anchor| anchor.no_historic_states_stored(split.slot)))
        {
            Ok(())
        } else {
            Err(StoreConfigError::IncompatibleStoreConfig {
                config: db_config,
                on_disk: on_disk_config.clone(),
            })
        }
    }

    /// Check that the configuration is valid.
    pub fn verify<E: EthSpec>(&self) -> Result<(), StoreConfigError> {
        self.verify_compression_level()?;
        self.verify_epochs_per_blob_prune()?;
        self.verify_epochs_per_state_diff::<E>()
    }

    /// Check that the compression level is valid.
    fn verify_compression_level(&self) -> Result<(), StoreConfigError> {
        if zstd::compression_level_range().contains(&self.compression_level) {
            Ok(())
        } else {
            Err(StoreConfigError::InvalidCompressionLevel {
                level: self.compression_level,
            })
        }
    }

    /// Check that the configuration is valid.
    pub fn verify_epochs_per_state_diff<E: EthSpec>(&self) -> Result<(), StoreConfigError> {
        // To build state diffs we need to be able to determine the previous state root from the
        // state itself, which requires reading back in the state_roots array.
        let max_supported = E::SlotsPerHistoricalRoot::to_u64() / E::slots_per_epoch();
        if self.epochs_per_state_diff <= max_supported {
            Ok(())
        } else {
            Err(StoreConfigError::InvalidEpochsPerStateDiff {
                epochs_per_state_diff: self.epochs_per_state_diff,
                max_supported,
            })
        }
    }

    /// Check that epochs_per_blob_prune is at least 1 epoch to avoid attempting to prune the same
    /// epochs over and over again.
    fn verify_epochs_per_blob_prune(&self) -> Result<(), StoreConfigError> {
        if self.epochs_per_blob_prune > 0 {
            Ok(())
        } else {
            Err(StoreConfigError::ZeroEpochsPerBlobPrune)
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

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{metadata::STATE_UPPER_LIMIT_NO_RETAIN, AnchorInfo, Split};
    use types::{Hash256, Slot};

    #[test]
    fn check_compatibility_ok() {
        let store_config = StoreConfig {
            linear_blocks: true,
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig {
            linear_blocks: true,
            hierarchy_config: store_config.hierarchy_config.clone(),
        };
        let split = Split::default();
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, None)
            .is_ok());
    }

    #[test]
    fn check_compatibility_linear_blocks_mismatch() {
        let store_config = StoreConfig {
            linear_blocks: true,
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig {
            linear_blocks: false,
            hierarchy_config: store_config.hierarchy_config.clone(),
        };
        let split = Split::default();
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, None)
            .is_err());
    }

    #[test]
    fn check_compatibility_hierarchy_config_incompatible() {
        let store_config = StoreConfig {
            linear_blocks: true,
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig {
            linear_blocks: true,
            hierarchy_config: HierarchyConfig {
                exponents: vec![5, 8, 11, 13, 16, 18, 21],
            },
        };
        let split = Split::default();
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, None)
            .is_err());
    }

    #[test]
    fn check_compatibility_hierarchy_config_update() {
        let store_config = StoreConfig {
            linear_blocks: true,
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig {
            linear_blocks: true,
            hierarchy_config: HierarchyConfig {
                exponents: vec![5, 8, 11, 13, 16, 18, 21],
            },
        };
        let split = Split::default();
        let anchor = AnchorInfo {
            anchor_slot: Slot::new(0),
            oldest_block_slot: Slot::new(0),
            oldest_block_parent: Hash256::zero(),
            state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
            state_lower_limit: Slot::new(0),
        };
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, Some(&anchor))
            .is_ok());
    }
}
