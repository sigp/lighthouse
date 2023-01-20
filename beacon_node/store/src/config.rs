use crate::{DBColumn, Error, StoreItem};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::{EthSpec, MinimalEthSpec};

pub const PREV_DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 2048;
pub const DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 8192;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 5;
pub const DEFAULT_BLOB_CACHE_SIZE: usize = 5;
pub const DEFAULT_EPOCHS_PER_BLOB_PRUNE: u64 = 1;
pub const DEFAULT_BLOB_PUNE_MARGIN_EPOCHS: Option<u64> = None;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Number of slots to wait between storing restore points in the freezer database.
    pub slots_per_restore_point: u64,
    /// Flag indicating whether the `slots_per_restore_point` was set explicitly by the user.
    pub slots_per_restore_point_set_explicitly: bool,
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: usize,
    /// Maximum number of blobs to store in the in-memory blob cache.
    pub blob_cache_size: usize,
    /// Whether to compact the database on initialization.
    pub compact_on_init: bool,
    /// Whether to compact the database during database pruning.
    pub compact_on_prune: bool,
    /// Whether to prune payloads on initialization and finalization.
    pub prune_payloads: bool,
    /// Whether to prune blobs older than the blob data availability boundary.
    pub prune_blobs: bool,
    /// Frequency of blob pruning in epochs. Default: every epoch.
    pub epochs_per_blob_prune: u64,
    /// The margin for blob pruning in epochs. The oldest blobs are pruned up until
    /// data_availability_boundary - blob_prune_margin_epochs. Default: 0.
    pub blob_prune_margin_epochs: Option<u64>,
}

/// Variant of `StoreConfig` that gets written to disk. Contains immutable configuration params.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OnDiskStoreConfig {
    pub slots_per_restore_point: u64,
}

#[derive(Debug, Clone)]
pub enum StoreConfigError {
    MismatchedSlotsPerRestorePoint { config: u64, on_disk: u64 },
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            // Safe default for tests, shouldn't ever be read by a CLI node.
            slots_per_restore_point: MinimalEthSpec::slots_per_historical_root() as u64,
            slots_per_restore_point_set_explicitly: false,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            blob_cache_size: DEFAULT_BLOB_CACHE_SIZE,
            compact_on_init: false,
            compact_on_prune: true,
            prune_payloads: true,
            prune_blobs: true,
            epochs_per_blob_prune: DEFAULT_EPOCHS_PER_BLOB_PRUNE,
            blob_prune_margin_epochs: DEFAULT_BLOB_PUNE_MARGIN_EPOCHS,
        }
    }
}

impl StoreConfig {
    pub fn as_disk_config(&self) -> OnDiskStoreConfig {
        OnDiskStoreConfig {
            slots_per_restore_point: self.slots_per_restore_point,
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
