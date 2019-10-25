mod block_cache;
mod deposit_cache;
mod deposit_log;
mod deposit_set;
pub mod http;
mod inner;
mod service;

pub use block_cache::{BlockCache, Eth1Block};
pub use deposit_cache::DepositCache;
pub use deposit_log::DepositLog;
pub use deposit_set::DepositSet;
pub use service::{BlockCacheUpdateOutcome, Config, DepositCacheUpdateOutcome, Error, Service};

use slog::Logger;
use std::ops::Range;
use std::time::Duration;
use types::{Deposit, Eth1Data, Hash256};

#[derive(Clone)]
pub struct BlockProposalService {
    pub core: Service,
}

impl BlockProposalService {
    pub fn new(config: Config, log: Logger) -> Self {
        Self {
            core: Service::new(config, log),
        }
    }

    /// Instantiates `self` from an existing service.
    pub fn from_service(service: Service) -> Self {
        Self { core: service }
    }

    /// Returns all the `Eth1Data` starting at the block with the `from` hash, up until the last
    /// cached block with a timestamp that is less than or equal to `to`.
    ///
    /// Blocks are returned in ascending order of block number.
    ///
    /// ## Errors
    ///
    /// - If a block with `from` hash is not found in the cache.
    /// - If any block within the `from` and `to` range was prior to the deployment of the deposit
    /// contract (specified in `Config`).
    pub fn get_eth1_data(&self, from: Hash256, to: Duration) -> Result<Vec<Eth1Data>, String> {
        let cache = self.core.blocks().read();

        let from = cache
            .iter()
            .position(|block| block.hash == from)
            .ok_or_else(|| format!("Block with hash {:?} is not in eth1 block cache", from))?;

        cache
            .iter()
            .skip(from)
            .take_while(|block| Duration::from_secs(block.timestamp) <= to)
            .map(|block| {
                block.clone().eth1_data().ok_or_else(|| {
                    "Attempted to get eth1 from blocks prior to deposit contract deployment"
                        .to_string()
                })
            })
            .collect()
    }

    /// Returns a list of `Deposit` objects, within the given deposit index `range`.
    ///
    /// The `deposit_count` is used to generate the proofs for the `Deposits`. For example, if we
    /// have 100 proofs, but the eth2 chain only acknowledges 50 of them, we must produce our
    /// proofs with respect to a tree size of 50.
    ///
    ///
    /// ## Errors
    ///
    /// - If `deposit_count` is larger than `range.end`.
    /// - There are not sufficient deposits in the tree to generate the proof.
    pub fn get_deposits(
        &self,
        range: Range<u64>,
        deposit_count: u64,
        tree_depth: usize,
    ) -> Result<(Hash256, Vec<Deposit>), String> {
        self.core
            .deposits()
            .read()
            .cache
            .get_deposits(range, deposit_count, tree_depth)
            .map_err(|e| format!("Failed to get deposits: {:?}", e))
    }
}
