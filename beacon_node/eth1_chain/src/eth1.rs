use std::cmp::Ordering;
use types::*;
use web3::types::*;

const ETH1_FOLLOW_DISTANCE: u64 = 1024; // Need to move this to eth2_config.toml

/// Interface for getting Eth1 chain data.
pub trait Eth1DataFetcher {
    /// Get block_header of the head of the chain.
    fn get_current_block_number(&self) -> Option<U256>;

    /// Get block_hash at given height.
    fn get_block_hash_by_height(&self, height: u64) -> Option<H256>;

    /// Get deposit contract root at given eth1 block-number.
    fn get_deposit_root(&self, block_number: Option<BlockNumber>) -> Option<H256>;

    /// Get `deposit_count` from DepositContract at given eth1 block_number.
    fn get_deposit_count(&self, block_number: Option<BlockNumber>) -> Option<u64>;

    /// Get `DepositEvent` events in given range.
    fn get_deposit_logs_in_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
    ) -> Option<Vec<Log>>;
}

/// Get `Eth1Data` object at a distance of `distance` from the perceived head of the currrent Eth1 chain.
pub fn get_eth1_data<T: Eth1DataFetcher>(distance: u64, eth1_fetcher: &T) -> Option<Eth1Data> {
    let current_block_number: U256 = eth1_fetcher.get_current_block_number()?;
    let block_number: U256 = current_block_number.checked_sub(distance.into())?;
    Some(Eth1Data {
        deposit_root: eth1_fetcher
            .get_deposit_root(Some(BlockNumber::Number(block_number.as_u64())))?,
        deposit_count: eth1_fetcher
            .get_deposit_count(Some(BlockNumber::Number(block_number.as_u64())))?,
        block_hash: eth1_fetcher.get_block_hash_by_height(block_number.as_u64())?,
    })
}

pub fn get_eth1_data_in_range<T: Eth1DataFetcher>(
    eth1_fetcher: &T,
    start: u64,
    end: u64,
) -> Vec<Eth1Data> {
    (start..end)
        .map(|h| get_eth1_data::<T>(h, &eth1_fetcher))
        .flatten()
        .collect::<Vec<Eth1Data>>()
}

//  From https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/validator/0_beacon-chain-validator.md#eth1-data
pub fn get_eth1_votes<T: EthSpec, F: Eth1DataFetcher>(
    state: BeaconState<T>,
    previous_eth1_distance: u64,
    eth1_fetcher: &F,
) -> Eth1Data {
    let new_eth1_data =
        get_eth1_data_in_range(eth1_fetcher, ETH1_FOLLOW_DISTANCE, 2 * ETH1_FOLLOW_DISTANCE);
    let all_eth1_data =
        get_eth1_data_in_range(eth1_fetcher, ETH1_FOLLOW_DISTANCE, previous_eth1_distance);
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
        .unwrap_or(get_eth1_data(ETH1_FOLLOW_DISTANCE, eth1_fetcher).unwrap()) //TODO: Better error handling
}
