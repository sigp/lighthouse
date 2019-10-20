use crate::http::{
    get_block, get_block_number, get_deposit_count, get_deposit_logs_in_range, get_deposit_root,
    Block as HttpBlock,
};
use crate::Config;
use crate::{block_cache::BlockCache, deposit_cache::DepositCache};
use parking_lot::RwLock;

#[derive(Default)]
pub struct DepositUpdater {
    pub cache: DepositCache,
    pub last_processed_block: Option<u64>,
}

#[derive(Default)]
pub struct Inner {
    pub block_cache: RwLock<BlockCache>,
    pub deposit_cache: RwLock<DepositUpdater>,
    pub config: Config,
}

impl Inner {
    /// Prunes the block cache to `self.target_block_cache_len`.
    ///
    /// Is a no-op if `self.target_block_cache_len` is `None`.
    pub fn prune_blocks(&self) {
        if let Some(block_cache_truncation) = self.config.block_cache_truncation {
            self.block_cache.write().truncate(block_cache_truncation);
        }
    }

    /*
    /// Returns the number of currently cached blocks.
    pub fn block_cache_len(&self) -> usize {
        self.block_cache.read().len()
    }

    /// Returns the number deposits available in the deposit cache.
    pub fn deposit_cache_len(&self) -> usize {
        self.deposit_cache.read().cache.len()
    }
    */
}
