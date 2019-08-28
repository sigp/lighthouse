use crate::types::Eth1DataFetcher;
use ethereum_types::H256;
use merkle_proof::*;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::marker::Send;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{Deposit, DepositData};
use web3::futures::Future;

/// Cache for all deposits received in DepositContract.
#[derive(Clone, Debug)]
pub struct DepositCache<F: Eth1DataFetcher> {
    /// Deposit index to deposit
    pub deposit_data: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    /// Last deposit index queried by beacon chain
    last_index: u64,
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher> DepositCache<F> {
    pub fn new(fetcher: Arc<F>) -> Self {
        DepositCache {
            deposit_data: Arc::new(RwLock::new(BTreeMap::new())),
            last_index: 0,
            fetcher,
        }
    }

    /// Return all the `DepositData` structs in given range.
    /// NOTE: Returns None if any of the indices in the range are absent
    /// as the deposit contract merkle root won't match.
    pub fn get_deposit_data(
        &self,
        from_deposit_index: u64,
        to_deposit_index: u64,
    ) -> Option<Vec<DepositData>> {
        let deposits_cache = self.deposit_data.read();
        let mut deposit_data = vec![];
        for deposit_index in from_deposit_index..to_deposit_index {
            let deposit = deposits_cache.get(&deposit_index);
            match deposit {
                None => return None, // Index missing in cache. Merkle proof won't verify
                Some(d) => deposit_data.push(d.clone()),
            }
        }
        Some(deposit_data)
    }

    /// Return all `Deposit` structs till given index.
    pub fn get_deposits_upto(&self, to_deposit_index: u64) -> Option<Vec<Deposit>> {
        let deposit_data = self.get_deposit_data(0, to_deposit_index)?;
        let deposit_data_hash: Vec<H256> = deposit_data
            .iter()
            .map(|n| H256::from_slice(&n.tree_hash_root()))
            .collect();
        let tree = MerkleTree::create(&deposit_data_hash, 32); // DEPOSIT_TREE_HEIGHT
        let deposits = deposit_data
            .into_iter()
            .enumerate()
            .map(|(i, val)| Deposit {
                proof: tree.generate_proof(i + 1, 32).1.into(),
                data: val,
            })
            .collect::<Vec<_>>();
        Some(deposits)
    }

    /// Returns a future that adds entries into the deposits map with new events.
    pub fn subscribe_deposit_logs(&self) -> impl Future<Item = (), Error = ()> + Send {
        let cache = self.deposit_data.clone();
        let event_future = self.fetcher.get_deposit_logs_subscription(cache);
        event_future.map_err(|e| println!("Eth1 error {:?}", e))
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
