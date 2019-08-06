use std::cmp::Ordering;
use types::*;
use crate::fetcher::Eth1DataFetcher;
use crate::cache::*;


const ETH1_FOLLOW_DISTANCE: u64 = 1024; // Need to move this to eth2_config.toml

//  From https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/validator/0_beacon-chain-validator.md#eth1-data
pub fn get_eth1_votes<T: EthSpec, F: Eth1DataFetcher>(
    state: BeaconState<T>,
    previous_eth1_distance: u64,
    eth1_cache: &mut Eth1Cache,
    eth1_fetcher: &F,
) -> Eth1Data {
    let new_eth1_data =
        eth1_cache.get_eth1_data_in_range(eth1_fetcher, ETH1_FOLLOW_DISTANCE, 2 * ETH1_FOLLOW_DISTANCE);
    let all_eth1_data =
        eth1_cache.get_eth1_data_in_range(eth1_fetcher, ETH1_FOLLOW_DISTANCE, previous_eth1_distance);
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
        .unwrap_or(eth1_cache.get_eth1_data(ETH1_FOLLOW_DISTANCE, eth1_fetcher).unwrap()) //TODO: Better error handling
}
