use crate::hdiff::HierarchyConfig;
use crate::superstruct;
use crate::{DBColumn, Error, StoreItem};
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use strum::{Display, EnumString, EnumVariantNames};
use types::EthSpec;
use types::non_zero_usize::new_non_zero_usize;
use zstd::{Decoder, Encoder};

#[cfg(all(feature = "redb", not(feature = "leveldb")))]
pub const DEFAULT_BACKEND: DatabaseBackend = DatabaseBackend::Redb;
#[cfg(feature = "leveldb")]
pub const DEFAULT_BACKEND: DatabaseBackend = DatabaseBackend::LevelDb;

pub const PREV_DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 2048;
pub const DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 8192;
pub const DEFAULT_EPOCHS_PER_STATE_DIFF: u64 = 8;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 0;
pub const DEFAULT_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(128);
pub const DEFAULT_STATE_CACHE_HEADROOM: NonZeroUsize = new_non_zero_usize(1);
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 1;
pub const DEFAULT_HISTORIC_STATE_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(1);
pub const DEFAULT_COLD_HDIFF_BUFFER_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(16);
pub const DEFAULT_HOT_HDIFF_BUFFER_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(1);
const EST_COMPRESSION_FACTOR: usize = 2;
pub const DEFAULT_EPOCHS_PER_BLOB_PRUNE: u64 = 1;
pub const DEFAULT_BLOB_PUNE_MARGIN_EPOCHS: u64 = 0;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: usize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: NonZeroUsize,
    /// Minimum number of states to cull from the state cache upon fullness.
    pub state_cache_headroom: NonZeroUsize,
    /// Compression level for blocks, state diffs and other compressed values.
    pub compression_level: i32,
    /// Maximum number of historic states to store in the in-memory historic state cache.
    pub historic_state_cache_size: NonZeroUsize,
    /// Maximum number of cold `HDiffBuffer`s to store in memory.
    pub cold_hdiff_buffer_cache_size: NonZeroUsize,
    /// Maximum number of hot `HDiffBuffers` to store in memory.
    pub hot_hdiff_buffer_cache_size: NonZeroUsize,
    /// Whether to compact the database on initialization.
    pub compact_on_init: bool,
    /// Whether to compact the database during database pruning.
    pub compact_on_prune: bool,
    /// Whether to prune payloads on initialization and finalization.
    pub prune_payloads: bool,
    /// Database backend to use.
    pub backend: DatabaseBackend,
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
    variants(V22),
    variant_attributes(derive(Debug, Clone, PartialEq, Eq, Encode, Decode))
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnDiskStoreConfig {
    /// Prefix byte to future-proof versions of the `OnDiskStoreConfig`.
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
            state_cache_headroom: DEFAULT_STATE_CACHE_HEADROOM,
            historic_state_cache_size: DEFAULT_HISTORIC_STATE_CACHE_SIZE,
            cold_hdiff_buffer_cache_size: DEFAULT_COLD_HDIFF_BUFFER_CACHE_SIZE,
            hot_hdiff_buffer_cache_size: DEFAULT_HOT_HDIFF_BUFFER_CACHE_SIZE,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            backend: DEFAULT_BACKEND,
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
    ) -> Result<(), StoreConfigError> {
        // We previously allowed the hierarchy exponents to change on non-archive nodes, but since
        // schema v24 and the use of hdiffs in the hot DB, changing will require a resync.
        let current_config = self.as_disk_config();
        if current_config != *on_disk_config {
            Err(StoreConfigError::IncompatibleStoreConfig {
                config: current_config,
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

    /// Compress bytes using zstd and the compression level from `self`.
    pub fn compress_bytes(&self, ssz_bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut compressed_value =
            Vec::with_capacity(self.estimate_compressed_size(ssz_bytes.len()));
        let mut encoder = Encoder::new(&mut compressed_value, self.compression_level)?;
        encoder.write_all(ssz_bytes)?;
        encoder.finish()?;
        Ok(compressed_value)
    }

    /// Decompress bytes compressed using zstd.
    pub fn decompress_bytes(&self, input: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut out = Vec::with_capacity(self.estimate_decompressed_size(input.len()));
        let mut decoder = Decoder::new(input)?;
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }
}

impl StoreItem for OnDiskStoreConfig {
    fn db_column() -> DBColumn {
        DBColumn::BeaconMeta
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        match self {
            OnDiskStoreConfig::V22(value) => value.as_ssz_bytes(),
        }
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.first() {
            Some(22) => Ok(Self::V22(OnDiskStoreConfigV22::from_ssz_bytes(bytes)?)),
            version_byte => Err(StoreConfigError::InvalidVersionByte(version_byte.copied()).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_compatibility_ok() {
        let store_config = StoreConfig {
            ..Default::default()
        };
        let on_disk_config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(
            store_config.hierarchy_config.clone(),
        ));
        assert!(store_config.check_compatibility(&on_disk_config).is_ok());
    }

    #[test]
    fn check_compatibility_hierarchy_config_incompatible() {
        let store_config = StoreConfig::default();
        let on_disk_config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(HierarchyConfig {
            exponents: vec![5, 8, 11, 13, 16, 18, 21],
        }));
        assert!(store_config.check_compatibility(&on_disk_config).is_err());
    }

    #[test]
    fn on_disk_config_v22_roundtrip() {
        let config = OnDiskStoreConfig::V22(OnDiskStoreConfigV22::new(<_>::default()));
        let bytes = config.as_store_bytes();
        assert_eq!(bytes[0], 22);
        let config_out = OnDiskStoreConfig::from_store_bytes(&bytes).unwrap();
        assert_eq!(config_out, config);
    }
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Display, EnumString, EnumVariantNames,
)]
#[strum(serialize_all = "lowercase")]
pub enum DatabaseBackend {
    #[cfg(feature = "leveldb")]
    LevelDb,
    #[cfg(feature = "redb")]
    Redb,
}
