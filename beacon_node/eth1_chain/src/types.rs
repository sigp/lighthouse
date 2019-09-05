use crate::error::{Error, Result};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::marker::{Send, Sync};
use std::sync::Arc;
use types::DepositData;
use web3::futures::Future;
use web3::types::*;

/// Interface for getting Eth1 chain data.
pub trait Eth1DataFetcher: Send + Sync + Clone {
    /// Get block_header of the head of the chain.
    fn get_current_block_number(&self) -> Box<dyn Future<Item = U256, Error = Error> + Send>;

    /// Get block_hash at given height.
    fn get_block_hash_by_height(
        &self,
        height: u64,
    ) -> Box<dyn Future<Item = Option<H256>, Error = Error> + Send>;

    /// Get deposit contract root at given eth1 block-number.
    fn get_deposit_root(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = H256, Error = Error> + Send>;

    /// Get `deposit_count` from DepositContract at given eth1 block_number.
    fn get_deposit_count(
        &self,
        block_number: Option<BlockNumber>,
    ) -> Box<dyn Future<Item = Result<u64>, Error = Error> + Send>;

    /// Returns a future which when called in periodic intervals, fetches all the logs
    /// from the deposit contract in the given range of block numbers and inserts
    /// it into the passed cache structure.
    fn get_deposit_logs_in_range(
        &self,
        start_block: BlockNumber,
        end_block: BlockNumber,
        cache: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send>;
}
