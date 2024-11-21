use crate::hdiff::HierarchyConfig;
use crate::{AnchorInfo, DBColumn, Error, Split, StoreItem};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::Write;
use std::num::NonZeroUsize;
use superstruct::superstruct;
use types::non_zero_usize::new_non_zero_usize;
use types::EthSpec;
use zstd::Encoder;

// Only used in tests. Mainnet sets a higher default on the CLI.
pub const DEFAULT_EPOCHS_PER_STATE_DIFF: u64 = 8;
pub const DEFAULT_BLOCK_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(64);
pub const DEFAULT_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(128);
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
pub const DEFAULT_HISTORIC_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(1);
pub const DEFAULT_HDIFF_BUFFER_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(16);
const EST_COMPRESSION_FACTOR: usize = 2;
pub const DEFAULT_EPOCHS_PER_BLOB_PRUNE: u64 = 1;
pub const DEFAULT_BLOB_PUNE_MARGIN_EPOCHS: u64 = 0;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: NonZeroUsize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: NonZeroUsize,
    /// Compression level for blocks, state diffs and other compressed values.
    pub compression_level: i32,
    /// Maximum number of historic states to store in the in-memory historic state cache.
    pub historic_state_cache_size: NonZeroUsize,
    /// Maximum number of `HDiffBuffer`s to store in memory.
    pub hdiff_buffer_cache_size: NonZeroUsize,
    /// Whether to compact the database on initialization.
    pub compact_on_init: bool,
    /// Whether to compact the database during database pruning.
    pub compact_on_prune: bool,
    /// Whether to prune payloads on initialization and finalization.
    pub prune_payloads: bool,
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
#[superstruct(
    variants(V1, V22),
    variant_attributes(derive(Debug, Clone, PartialEq, Eq, Encode, Decode))
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnDiskStoreConfig {
    #[superstruct(only(V1))]
    pub slots_per_restore_point: u64,
    /// Prefix byte to future-proof versions of the `OnDiskStoreConfig` post V1
    #[superstruct(only(V22))]
    version_byte: u8,
    #[superstruct(only(V22))]
    pub hierarchy_config: HierarchyConfig,
}

impl OnDiskStoreConfigV22 {
    fn new(hierarchy_config: HierarchyConfig) -> Self {
        Self {
            version_byte: 22,
            hierarchy_config,
        }
    }
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
    ZeroEpochsPerBlobPrune,
    InvalidVersionByte(Option<u8>),
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            state_cache_size: DEFAULT_STATE_CACHE_SIZE,
            historic_state_cache_size: DEFAULT_HISTORIC_STATE_CACHE_SIZE,
            hdiff_buffer_cache_size: DEFAULT_HDIFF_BUFFER_CACHE_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            hierarchy_config: HierarchyConfig::default(),
            prune_blobs: true,
            epochs_per_blob_prune: DEFAULT_EPOCHS_PER_BLOB_PRUNE,
            blob_prune_margin_epochs: DEFAULT_BLOB_PUNE_MARGIN_EPOCHS,
        }
    }
}

impl StoreConfig {
    pub fn as_disk_config(&self) -> OnDiskStoreConfig {
        OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(self.hierarchy_config.clone()))
    }

    pub fn check_compatibility(
        &self,
        on_disk_config: &OnDiskStoreConfig,
        split: &Split,
        anchor: &AnchorInfo,
    ) -> Result<(), StoreConfigError> {
        // Allow changing the hierarchy exponents if no historic states are stored.
        let no_historic_states_stored = anchor.no_historic_states_stored(split.slot);
        let hierarchy_config_changed =
            if let Ok(on_disk_hierarchy_config) = on_disk_config.hierarchy_config() {
                *on_disk_hierarchy_config != self.hierarchy_config
            } else {
                false
            };

        if hierarchy_config_changed && !no_historic_states_stored {
            Err(StoreConfigError::IncompatibleStoreConfig {
                config: self.as_disk_config(),
                on_disk: on_disk_config.clone(),
            })
        } else {
            Ok(())
        }
    }

    /// Check that the configuration is valid.
    pub fn verify<E: EthSpec>(&self) -> Result<(), StoreConfigError> {
        self.verify_compression_level()?;
        self.verify_epochs_per_blob_prune()
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
        // This is a rough estimate, but for our data it seems that all non-zero compression levels
        // provide a similar compression ratio.
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
        match self {
            OnDiskStoreConfig::V1(value) => value.as_ssz_bytes(),
            OnDiskStoreConfig::V22(value) => value.as_ssz_bytes(),
        }
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // NOTE: V22 config can never be deserialized as a V1 because the minimum length of its
        // serialization is: 1 prefix byte + 1 offset (OnDiskStoreConfigV1 container) +
        // 1 offset (HierarchyConfig container) = 9.
        if let Ok(value) = OnDiskStoreConfigV1::from_ssz_bytes(bytes) {
            return Ok(Self::V1(value));
        }

        Ok(Self::V22(OnDiskStoreConfigV22::from_ssz_bytes(bytes)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        metadata::{ANCHOR_FOR_ARCHIVE_NODE, ANCHOR_UNINITIALIZED, STATE_UPPER_LIMIT_NO_RETAIN},
        AnchorInfo, Split,
    };
    use ssz::DecodeError;
    use types::{Hash256, Slot};

    #[test]
    fn check_compatibility_ok() {
        let store_config = StoreConfig {
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(
            store_config.hierarchy_config.clone(),
        ));
        let split = Split::default();
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, &ANCHOR_UNINITIALIZED)
            .is_ok());
    }

    #[test]
    fn check_compatibility_after_migration() {
        let store_config = StoreConfig {
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig::V1(OnDiskStoreConfigV1 {
            slots_per_restore_point: 8192,
        });
        let split = Split::default();
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, &ANCHOR_UNINITIALIZED)
            .is_ok());
    }

    #[test]
    fn check_compatibility_hierarchy_config_incompatible() {
        let store_config = StoreConfig::default();
        let on_disk_config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(HierarchyConfig {
            exponents: vec![5, 8, 11, 13, 16, 18, 21],
        }));
        let split = Split {
            slot: Slot::new(32),
            ..Default::default()
        };
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, &ANCHOR_FOR_ARCHIVE_NODE)
            .is_err());
    }

    #[test]
    fn check_compatibility_hierarchy_config_update() {
        let store_config = StoreConfig {
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(HierarchyConfig {
            exponents: vec![5, 8, 11, 13, 16, 18, 21],
        }));
        let split = Split::default();
        let anchor = AnchorInfo {
            anchor_slot: Slot::new(0),
            oldest_block_slot: Slot::new(0),
            oldest_block_parent: Hash256::ZERO,
            state_upper_limit: STATE_UPPER_LIMIT_NO_RETAIN,
            state_lower_limit: Slot::new(0),
        };
        assert!(store_config
            .check_compatibility(&on_disk_config, &split, &anchor)
            .is_ok());
    }

    #[test]
    fn serde_on_disk_config_v0_from_v1_default() {
        let config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(<_>::default()));
        let config_bytes = config.as_store_bytes();
        // On a downgrade, the previous version of lighthouse will attempt to deserialize the
        // prefixed V22 as just the V1 version.
        assert_eq!(
            OnDiskStoreConfigV1::from_ssz_bytes(&config_bytes).unwrap_err(),
            DecodeError::InvalidByteLength {
                len: 16,
                expected: 8
            },
        );
    }

    #[test]
    fn serde_on_disk_config_v0_from_v1_empty() {
        let config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(HierarchyConfig {
            exponents: vec![],
        }));
        let config_bytes = config.as_store_bytes();
        // On a downgrade, the previous version of lighthouse will attempt to deserialize the
        // prefixed V22 as just the V1 version.
        assert_eq!(
            OnDiskStoreConfigV1::from_ssz_bytes(&config_bytes).unwrap_err(),
            DecodeError::InvalidByteLength {
                len: 9,
                expected: 8
            },
        );
    }

    #[test]
    fn serde_on_disk_config_v1_roundtrip() {
        let config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(<_>::default()));
        let bytes = config.as_store_bytes();
        assert_eq!(bytes[0], 22);
        let config_out = OnDiskStoreConfig::from_store_bytes(&bytes).unwrap();
        assert_eq!(config_out, config);
    }
}
