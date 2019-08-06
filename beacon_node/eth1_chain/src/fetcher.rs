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