#[macro_use]
extern crate lazy_static;

mod block_cache;
mod deposit_cache;
mod inner;
mod metrics;
mod service;

pub use block_cache::{BlockCache, Eth1Block};
pub use deposit_cache::{DepositCache, SszDepositCache, SszDepositCacheV1, SszDepositCacheV13};
pub use execution_layer::http::deposit_log::DepositLog;
pub use inner::{SszEth1Cache, SszEth1CacheV1, SszEth1CacheV13};
pub use service::{
    BlockCacheUpdateOutcome, Config, DepositCacheUpdateOutcome, Error, Eth1Endpoint, Service,
    DEFAULT_CHAIN_ID,
};
