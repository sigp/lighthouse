use types::Eth1Data;
use web3::types::*;

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
