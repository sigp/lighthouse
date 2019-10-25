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
    pub config: RwLock<Config>,
}

impl Inner {
    /// Prunes the block cache to `self.target_block_cache_len`.
    ///
    /// Is a no-op if `self.target_block_cache_len` is `None`.
    pub fn prune_blocks(&self) {
        if let Some(block_cache_truncation) = self.config.read().block_cache_truncation {
            self.block_cache.write().truncate(block_cache_truncation);
        }
    }

    /// Updates the configuration in `self to be `new_config`.
    ///
    /// Will truncate the block cache if the new configure specifies truncation.
    pub fn update_config(&self, new_config: Config) -> Result<(), String> {
        let mut old_config = self.config.write();

        if new_config.deposit_contract_deploy_block != old_config.deposit_contract_deploy_block {
            // This may be possible, I just haven't looked into the details to ensure it's safe.
            Err("Updating deposit_contract_deploy_block is not supported".to_string())
        } else {
            *old_config = new_config;

            // Prevents a locking condition when calling prune_blocks.
            drop(old_config);

            self.prune_blocks();

            Ok(())
        }
    }
}
