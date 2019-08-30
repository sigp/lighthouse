use crate::error::Error;
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
    ) -> Box<dyn Future<Item = Result<u64, Error>, Error = Error> + Send>;

    /// Returns a future which subscribes to `DepositEvent` events and inserts the
    /// parsed deposit into the passed cache structure everytime an event is emitted.
    fn get_deposit_logs_subscription(
        &self,
        cache: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send>;
}

/// Config for an Eth1 chain contract.
#[derive(Debug, Clone)]
pub struct ContractConfig {
    /// Deployed address in eth1 chain.
    pub address: Address,
    /// Contract abi.
    pub abi: Vec<u8>,
}
