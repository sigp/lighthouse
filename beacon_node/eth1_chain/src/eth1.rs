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

impl<F: Eth1DataFetcher> Eth1<F> {
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

pub fn run<F: Eth1DataFetcher>(
    eth1: &'static mut Eth1<F>,
    executor: &TaskExecutor,
    log: &slog::Logger,
) {
    let log = log.new(o!("service" => "eth1_chain"));

    // Run a task for calling `update_cache` periodically.
    let eth1_block_time_seconds: u64 = 15;
    let eth1_block_interval: u64 = 15;
    let interval_log = log.clone();
    let interval = {
        // Set the interval to start every 15 blocks
        let update_duration = Duration::from_secs(eth1_block_interval * eth1_block_time_seconds);
        Interval::new(Instant::now(), update_duration)
            .map_err(move |_| warn!(interval_log, "Interval timer failing"))
    };
    let eth1_data_cache = eth1.eth1_data_cache.clone();
    let cache_log = log.clone();
    info!(cache_log, "Cache updation service started..");
    executor.spawn(interval.for_each(move |_| {
        let cache_log = cache_log.clone();
        eth1_data_cache.update_cache().and_then(move |_| {
            debug!(cache_log.clone(), "Updating eth1 data cache..");
            Ok(())
        })
    }));

    // Run a task for listening to contract events and updating deposits cache.
    let eth1_deposit_cache = eth1.deposit_cache.clone();
    let deposit_log = log.clone();
    info!(deposit_log, "Deposit service started..");
    executor.spawn(
        eth1_deposit_cache
            .subscribe_deposit_logs()
            .map_err(move |_| warn!(deposit_log, "Error running deposit service..")),
    );
}
