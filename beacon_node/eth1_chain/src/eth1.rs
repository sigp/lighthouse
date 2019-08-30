use crate::cache::*;
use crate::deposits::*;
use crate::types::Eth1DataFetcher;
use slog::{debug, info, o, warn};
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use web3::futures::{Future, Stream};

use types::*;

const ETH1_FOLLOW_DISTANCE: u64 = 1024; // Need to move this to eth2_config.toml

#[derive(Clone, Debug)]
pub struct Eth1<F: Eth1DataFetcher> {
    /// Cache for storing block_number to Eth1Data from the deposit contract.
    pub eth1_data_cache: Eth1DataCache<F>,
    /// Cache for storing deposit_index to Deposits received from deposit contract.
    pub deposit_cache: DepositCache<F>,
    /// Eth1 data fetcher
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher + 'static> Eth1<F> {
    pub fn new(fetcher: F) -> Self {
        let fetcher_arc = Arc::new(fetcher);
        Eth1 {
            eth1_data_cache: Eth1DataCache::new(fetcher_arc.clone()),
            deposit_cache: DepositCache::new(fetcher_arc.clone()),
            fetcher: fetcher_arc,
        }
    }

    /// Get Eth1Votes with highest votes in given voting period.
    /// From https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/validator/0_beacon-chain-validator.md#eth1-data
    pub fn get_eth1_votes<T: EthSpec>(
        &mut self,
        state: BeaconState<T>,
        previous_eth1_distance: u64,
    ) -> Eth1Data {
        let new_eth1_data = self
            .eth1_data_cache
            .get_eth1_data_in_range(ETH1_FOLLOW_DISTANCE, 2 * ETH1_FOLLOW_DISTANCE);
        let all_eth1_data = self
            .eth1_data_cache
            .get_eth1_data_in_range(ETH1_FOLLOW_DISTANCE, previous_eth1_distance);
        let mut valid_votes: Vec<Eth1Data> = vec![];
        for (slot, vote) in state.eth1_data_votes.iter().enumerate() {
            let period_tail: bool = (slot as u64 % T::SlotsPerEth1VotingPeriod::to_u64())
                >= ((T::SlotsPerEth1VotingPeriod::to_u64() as f64).sqrt() as u64 + 1);
            if new_eth1_data.contains(vote) || (period_tail && all_eth1_data.contains(vote)) {
                valid_votes.push(vote.clone());
            }
        }
        valid_votes
            .iter()
            .cloned()
            .max_by(|x, y| {
                let mut result = valid_votes
                    .iter()
                    .filter(|n| *n == x)
                    .count()
                    .cmp(&valid_votes.iter().filter(|n| *n == y).count());
                if result == Ordering::Equal {
                    result = all_eth1_data
                        .iter()
                        .position(|s| s == x)
                        .cmp(&all_eth1_data.iter().position(|s| s == y));
                }
                result
            })
            .unwrap_or(
                self.eth1_data_cache
                    .get_eth1_data(ETH1_FOLLOW_DISTANCE)
                    .unwrap(),
            ) //TODO: Better error handling
    }
}

pub fn run<F: Eth1DataFetcher + 'static>(
    eth1: Eth1<F>,
    executor: &TaskExecutor,
    log: &slog::Logger,
) {
    let log = log.new(o!("service" => "eth1_chain"));

    // Run a task for calling `update_cache` periodically.
    let eth1_block_time_seconds: u64 = 5; // Approximate block time for eth1 chain.
    let eth1_block_interval: u64 = 3; // Interval of eth1 blocks to update eth1_data_cache.
    let interval_log = log.clone();
    let eth1_data_interval = {
        // Set the interval to fire every `eth1_block_interval` blocks.
        let update_duration = Duration::from_secs(eth1_block_interval * eth1_block_time_seconds);
        Interval::new(Instant::now(), update_duration)
            .map_err(move |_| warn!(interval_log, "Interval timer failing"))
    };
    let eth1_data_cache = eth1.eth1_data_cache.clone();
    let eth1_cache_log = log.clone();
    info!(eth1_cache_log, "Cache updation service started");
    executor.spawn(eth1_data_interval.for_each(move |_| {
        let log = eth1_cache_log.clone();
        eth1_data_cache
            .update_cache(eth1_block_interval + 1) // distance of block_interval + safety_interval
            .and_then(move |_| {
                debug!(log, "Updating eth1 data cache");
                Ok(())
            })
            .map_err(|e| println!("Updating eth1 cache failed {:?}", e))
    }));

    // Run a task for calling `update_deposits` periodically.
    let deposits_updation_interval = 40; // Interval of eth1 blocks to update deposits.
    let interval_log = log.clone();
    let deposits_interval = {
        // Set the interval to fire every `deposits_updation_interval` blocks
        let update_duration =
            Duration::from_secs(deposits_updation_interval * eth1_block_time_seconds);
        Interval::new(Instant::now(), update_duration)
            .map_err(move |_| warn!(interval_log, "Interval timer failing"))
    };
    let eth1_deposit_cache = eth1.deposit_cache.clone();
    let confirmations = 10;
    let deposit_log = log.clone();
    info!(deposit_log, "Deposits updation service started");
    executor.spawn(deposits_interval.for_each(move |_| {
        let deposit_log = deposit_log.clone();
        eth1_deposit_cache
            .update_deposits(confirmations) // distance of block_interval + safety_interval
            .and_then(move |_| {
                debug!(deposit_log, "Updating deposits cache");
                Ok(())
            })
            .map_err(|e| println!("Updating deposits cache failed {:?}", e))
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
    #[macro_use]
    use slog;
    use crate::types::ContractConfig;
    use crate::web3_fetcher::Web3DataFetcher;
    use slog_async;
    use slog_term;
    use web3::types::Address;

    use slog::Drain;

    fn setup_log() -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        let _log = slog::Logger::root(drain, o!());
        _log
    }

    fn setup_w3() -> Web3DataFetcher {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        return w3;
    }

    #[test]
    fn test_integration() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        println!("Testing");
        let executor = runtime.executor();
        let log = setup_log();
        let w3 = setup_w3();
        let eth1 = Eth1::new(w3);
        run(eth1, &executor, &log);
        runtime.shutdown_on_idle().wait().unwrap();
    }
}
