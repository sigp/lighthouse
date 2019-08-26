use crate::types::Eth1DataFetcher;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::marker::Send;
use std::sync::Arc;
use types::DepositData;
use web3::futures::Future;

/// Cache for all deposits received in DepositContract.
#[derive(Clone, Debug)]
pub struct DepositCache<F: Eth1DataFetcher> {
    /// Deposit index to deposit
    pub deposits: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    /// Last deposit index queried by beacon chain
    last_index: u64,
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher> DepositCache<F> {
    pub fn new(fetcher: Arc<F>) -> Self {
        DepositCache {
            deposits: Arc::new(RwLock::new(BTreeMap::new())),
            last_index: 0,
            fetcher,
        }
    }

    /// Return all the deposits received from self.last_index till to_deposit_index.
    pub fn get_deposit_data(&self, to_deposit_index: u64) -> Option<Vec<DepositData>> {
        let deposits_cache = self.deposits.read();
        let mut deposit_data = vec![];
        for deposit_index in 0..to_deposit_index {
            let deposit = deposits_cache.get(&deposit_index);
            match deposit {
                None => return None, // Index missing in cache. Merkle proof won't verify
                Some(d) => deposit_data.push(d.clone()),
            }
        }
        Some(deposit_data)
    }

    /// Returns a future that adds entries into the deposits map with new events.
    pub fn subscribe_deposit_logs(&self) -> impl Future<Item = (), Error = ()> + Send {
        let cache = self.deposits.clone();
        let event_future = self.fetcher.get_deposit_logs_subscription(cache);
        event_future
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContractConfig;
    use crate::web3_fetcher::Web3DataFetcher;
    use tokio;
    use tokio::runtime::TaskExecutor;
    use web3::types::Address;

    fn run(executor: &TaskExecutor) {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Arc::new(Web3DataFetcher::new(
            "ws://localhost:8545",
            deposit_contract,
        ));
        let cache = Arc::new(DepositCache::new(w3));
        let event_future = cache.subscribe_deposit_logs();
        executor.spawn(event_future);
    }

    #[test]
    // Check if depositing to eth1 chain updates the deposit_cache
    fn test_logs_updation() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let executor = runtime.executor();
        run(&executor);
        runtime.shutdown_on_idle().wait().unwrap();
    }
}
