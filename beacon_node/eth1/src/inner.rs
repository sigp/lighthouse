use crate::Config;
use crate::{
    block_cache::{BlockCache, Eth1Block},
    deposit_cache::{DepositCache, SszDepositCache},
    service::EndpointsCache,
};
use parking_lot::RwLock;
use ssz::four_byte_option_impl;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::ChainSpec;

// Define "legacy" implementations of `Option<u64>` which use four bytes for encoding the union
// selector.
four_byte_option_impl!(four_byte_option_u64, u64);

#[derive(Default)]
pub struct DepositUpdater {
    pub cache: DepositCache,
    pub last_processed_block: Option<u64>,
}

impl DepositUpdater {
    pub fn new(deposit_contract_deploy_block: u64) -> Self {
        let cache = DepositCache::new(deposit_contract_deploy_block);
        DepositUpdater {
            cache,
            last_processed_block: None,
        }
    }
}

#[derive(Default)]
pub struct Inner {
    pub block_cache: RwLock<BlockCache>,
    pub deposit_cache: RwLock<DepositUpdater>,
    pub endpoints_cache: RwLock<Option<Arc<EndpointsCache>>>,
    pub config: RwLock<Config>,
    pub remote_head_block: RwLock<Option<Eth1Block>>,
    pub spec: ChainSpec,
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

    /// Encode the eth1 block and deposit cache as bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        let ssz_eth1_cache = SszEth1Cache::from_inner(self);
        ssz_eth1_cache.as_ssz_bytes()
    }

    /// Recover `Inner` given byte representation of eth1 deposit and block caches.
    pub fn from_bytes(bytes: &[u8], config: Config, spec: ChainSpec) -> Result<Self, String> {
        let ssz_cache = SszEth1Cache::from_ssz_bytes(bytes)
            .map_err(|e| format!("Ssz decoding error: {:?}", e))?;
        ssz_cache.to_inner(config, spec)
    }

    /// Returns a reference to the specification.
    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }
}

#[derive(Encode, Decode, Clone)]
pub struct SszEth1Cache {
    block_cache: BlockCache,
    deposit_cache: SszDepositCache,
    #[ssz(with = "four_byte_option_u64")]
    last_processed_block: Option<u64>,
}

impl SszEth1Cache {
    pub fn from_inner(inner: &Inner) -> Self {
        let deposit_updater = inner.deposit_cache.read();
        let block_cache = inner.block_cache.read();
        Self {
            block_cache: (*block_cache).clone(),
            deposit_cache: SszDepositCache::from_deposit_cache(&deposit_updater.cache),
            last_processed_block: deposit_updater.last_processed_block,
        }
    }

    pub fn to_inner(&self, config: Config, spec: ChainSpec) -> Result<Inner, String> {
        Ok(Inner {
            block_cache: RwLock::new(self.block_cache.clone()),
            deposit_cache: RwLock::new(DepositUpdater {
                cache: self.deposit_cache.to_deposit_cache()?,
                last_processed_block: self.last_processed_block,
            }),
            endpoints_cache: RwLock::new(None),
            // Set the remote head_block zero when creating a new instance. We only care about
            // present and future eth1 nodes.
            remote_head_block: RwLock::new(None),
            config: RwLock::new(config),
            spec,
        })
    }
}
