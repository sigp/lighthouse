use serde_derive::{Deserialize, Serialize};

pub const DEFAULT_IMPORT_BLOCK_MAX_SKIP_SLOTS: u64 = 10 * 32;

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ChainConfig {
    /// Maximum number of slots to skip when importing a block.
    ///
    /// If `None`, there is no limit.
    pub import_block_max_skip_slots: Option<u64>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            import_block_max_skip_slots: Some(DEFAULT_IMPORT_BLOCK_MAX_SKIP_SLOTS),
        }
    }
}
