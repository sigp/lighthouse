#[macro_use]
extern crate lazy_static;

mod block_cache;
mod deposit_cache;
mod inner;
mod metrics;
mod service;

pub use block_cache::{BlockCache, Eth1Block};
pub use deposit_cache::DepositCache;
pub use execution_layer::http::deposit_log::DepositLog;
pub use inner::SszEth1Cache;
pub use service::{
    BlockCacheUpdateOutcome, Config, DepositCacheUpdateOutcome, Error, Eth1Endpoint, Service,
    DEFAULT_CHAIN_ID,
};
