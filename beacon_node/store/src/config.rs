use serde_derive::{Deserialize, Serialize};
use types::{EthSpec, MinimalEthSpec};

pub const DEFAULT_SLOTS_PER_RESTORE_POINT: u64 = 2048;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 5;
pub const DEFAULT_STATE_CACHE_SIZE: usize = 5;

/// Database configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Number of slots to wait between storing restore points in the freezer database.
    pub slots_per_restore_point: u64,
    /// Maximum number of blocks to store in the in-memory block cache.
    pub block_cache_size: usize,
    /// Maximum number of states to store in the in-memory state cache.
    pub state_cache_size: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            // Safe default for tests, shouldn't ever be read by a CLI node.
            slots_per_restore_point: MinimalEthSpec::slots_per_historical_root() as u64,
            block_cache_size: DEFAULT_BLOCK_CACHE_SIZE,
            state_cache_size: DEFAULT_STATE_CACHE_SIZE,
        }
    }
}
