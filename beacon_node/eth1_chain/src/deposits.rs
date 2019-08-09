use crate::fetcher::Eth1DataFetcher;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use types::DepositData;
use web3::futures::{Future};

/// Cache for all deposits received in DepositContract.
pub struct DepositCache {
    /// Deposit index to deposit
    pub deposits: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    /// Last deposit index queried by beacon chain
    last_index: u64,
}

impl DepositCache {
    pub fn new() -> Self {
        DepositCache {
            deposits: Arc::new(RwLock::new(BTreeMap::new())),
            last_index: 0,
        }
    }

    /// Return all the deposits received from self.last_index till to_deposit_index.
    pub fn get_deposit_data(&self, to_deposit_index: u64) -> Option<Vec<DepositData>> {
        let deposits_cache = self.deposits.read();
        let mut deposit_data = vec![];
        for deposit_index in self.last_index..to_deposit_index {
            let deposit = deposits_cache.get(&deposit_index);
            match deposit {
                None => return None, // Index missing in cache. Merkle proof won't verify
                Some(d) => deposit_data.push(d.clone()),
            }
        }
        Some(deposit_data)
    }

    pub fn subscribe_deposit_logs<T: Eth1DataFetcher>(
        &self,
        w3: &T,
    ) -> impl Future<Item = (), Error = ()> {
        let cache = self.deposits.clone();
        let event_future = w3.get_deposit_logs_subscription(cache);
        event_future
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web3_fetcher::{ContractConfig, Web3DataFetcher};
    use std::time::{Duration, Instant};
    use tokio::timer::Interval;
    use tokio_core::reactor::Core;
    use web3::types::Address;
    use web3::futures::Stream;

    #[test]
    fn test_logs_updation() {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        let cache = Arc::new(DepositCache::new());
        let new_cache = cache.clone();

        let task = Interval::new(Instant::now(), Duration::from_millis(1000))
            .take(100)
            .for_each(move |instant| {
                println!("Length of {:?}", new_cache.deposits.read().len());
                Ok(())
            })
            .map_err(|_| ());
        let event_future = cache.subscribe_deposit_logs(&w3);
        let pair = task.join(event_future).map_err(|_| ());
        let mut core = Core::new().unwrap();
        core.run(pair).unwrap();
    }
}
