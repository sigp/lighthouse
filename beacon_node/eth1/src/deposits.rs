use crate::error::{Error, Result};
use crate::types::Eth1DataFetcher;
use ethereum_types::{H256, U256};
use merkle_proof::*;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::marker::Send;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{Deposit, DepositData};
use web3::futures::Future;
use web3::types::BlockNumber;

/// Cache for all deposits received in DepositContract.
#[derive(Clone, Debug)]
pub struct DepositCache<F: Eth1DataFetcher> {
    /// Deposit index to deposit
    pub deposit_data: Arc<RwLock<BTreeMap<u64, DepositData>>>,
    /// Last deposit index queried by beacon chain
    last_index: u64,
    /// Last block_number which was queried for `DepositEvent`
    last_fetched: Arc<RwLock<u64>>,
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher> DepositCache<F> {
    pub fn new(fetcher: Arc<F>) -> Self {
        DepositCache {
            deposit_data: Arc::new(RwLock::new(BTreeMap::new())),
            last_index: 0,
            // Note: Should ideally start from block where Eth1 chain starts accepting deposits.
            last_fetched: Arc::new(RwLock::new(0)),
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
    ) -> Result<Vec<DepositData>> {
        let deposits_cache = self.deposit_data.read();
        let mut deposit_data = vec![];
        for deposit_index in from_deposit_index..to_deposit_index {
            let deposit = deposits_cache.get(&deposit_index);
            match deposit {
                None => return Err(Error::MissingDeposit(deposit_index)), // Index missing in cache. Merkle proof won't verify
                Some(d) => deposit_data.push(d.clone()),
            }
        }
        Ok(deposit_data)
    }

    /// Return all `Deposit` structs till given index.
    /// TODO: construct incremental merkle tree. Repeated construction wasteful.
    pub fn get_deposits_in_range(
        &self,
        from_deposit_index: u64,
        to_deposit_index: u64,
    ) -> Result<Vec<Deposit>> {
        let deposit_data = self.get_deposit_data(0, to_deposit_index)?;
        let deposit_data_hash: Vec<H256> = deposit_data
            .iter()
            .map(|n| H256::from_slice(&n.tree_hash_root()))
            .collect();
        let tree = MerkleTree::create(&deposit_data_hash, 32); // DEPOSIT_TREE_HEIGHT
        let deposits = deposit_data
            .into_iter()
            .enumerate()
            .skip_while(|x| (x.0 as u64) < from_deposit_index)
            .map(|(i, val)| Deposit {
                proof: tree.generate_proof(i + 1, 32).1.into(),
                data: val,
            })
            .collect::<Vec<_>>();
        Ok(deposits)
    }

    /// Update deposits from last updated point to `current_block_number - confirmations`.
    pub fn update_deposits(
        &self,
        confirmations: u64,
    ) -> impl Future<Item = (), Error = Error> + Send {
        let fetcher = self.fetcher.clone();
        let last_fetched = self.last_fetched.clone();
        let deposits = self.deposit_data.clone();
        let future = self
            .fetcher
            .get_current_block_number()
            .and_then(move |curr_block_number| {
                let end_block: U256 = curr_block_number
                    .checked_sub(confirmations.into())
                    .unwrap_or(U256::zero());
                fetcher
                    .get_deposit_logs_in_range(
                        BlockNumber::Number(*last_fetched.clone().read()),
                        BlockNumber::Number(end_block.as_u64()),
                        deposits,
                    )
                    .and_then(move |_| {
                        let mut last_fetched_write = last_fetched.write();
                        *last_fetched_write = curr_block_number.as_u64();
                        Ok(())
                    })
            });
        future
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::web3_fetcher::Web3DataFetcher;
    use std::time::{Duration, Instant};
    use tokio;
    use tokio::timer::Interval;
    use web3::futures::Stream;

    fn setup() -> Web3DataFetcher {
        let config = Config::default();
        let w3 = Web3DataFetcher::new(&config.endpoint, &config.address);
        return w3.unwrap();
    }

    #[test]
    fn test_logs_updation() {
        let w3 = setup();
        let interval = {
            let update_duration = Duration::from_secs(15);
            Interval::new(Instant::now(), update_duration).map_err(|e| println!("{:?}", e))
        };

        let deposit_cache = Arc::new(DepositCache::new(Arc::new(w3)));
        let task = interval.take(100).for_each(move |_| {
            // let c = cache_inside.clone();
            deposit_cache
                .update_deposits(0)
                .and_then(move |_| Ok(()))
                .map_err(|e| println!("Some error {:?}", e))
        });
        tokio::run(task.map_err(|e| println!("Some error {:?}", e)));
    }
}
