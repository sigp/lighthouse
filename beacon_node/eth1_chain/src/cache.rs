use crate::error::Eth1Error;
use crate::types::Eth1DataFetcher;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio;
use types::*;
use web3::futures::*;
use web3::types::*;

/// Cache for recent Eth1Data fetched from the Eth1 chain.
#[derive(Clone, Debug)]
pub struct Eth1DataCache<F: Eth1DataFetcher> {
    cache: Arc<RwLock<BTreeMap<U256, Eth1Data>>>,
    last_block: Arc<RwLock<u64>>,
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher> Eth1DataCache<F> {
    pub fn new(fetcher: Arc<F>) -> Self {
        Eth1DataCache {
            cache: Arc::new(RwLock::new(BTreeMap::new())),
            // Note: Should ideally start from block where Eth1 chain starts accepting deposits.
            last_block: Arc::new(RwLock::new(0)),
            fetcher: fetcher,
        }
    }

    /// Called periodically to populate the cache with Eth1Data
    /// from most recent blocks upto `distance`.
    pub fn update_cache(&self, distance: u64) -> impl Future<Item = (), Error = Eth1Error> + Send {
        let cache_updated = self.cache.clone();
        let last_block = self.last_block.clone();
        let fetcher = self.fetcher.clone();
        let future = self
            .fetcher
            .get_current_block_number()
            .and_then(move |curr_block_number| {
                fetch_eth1_data_in_range(0, distance, curr_block_number, fetcher)
                    .for_each(move |data| {
                        let data = data?;
                        println!("Cache data: {:#?}", data);
                        let mut eth1_cache = cache_updated.write();
                        eth1_cache.insert(data.0, data.1);
                        Ok(())
                    })
                    .and_then(move |_| {
                        let mut last_block_updated = last_block.write();
                        *last_block_updated = curr_block_number.as_u64();
                        // TODO: Delete older stuff
                        Ok(())
                    })
            });
        future
    }

    /// Get `Eth1Data` object at a distance of `distance` from the perceived head of the currrent Eth1 chain.
    /// Returns the object from the cache if present, else fetches from Eth1Fetcher.
    pub fn get_eth1_data(&mut self, distance: u64) -> Option<Eth1Data> {
        let current_block_number: U256 =
            tokio::runtime::current_thread::block_on_all(self.fetcher.get_current_block_number())
                .ok()?;
        let block_number: U256 = current_block_number.checked_sub(distance.into())?;
        if let Some(result) = self.cache.read().get(&block_number) {
            return Some(result.clone());
        } else {
            // Note: current_thread::block_on_all() might not be safe here since
            // it waits for other spawned futures to complete on current thread.
            if let Ok((block_number, eth1_data)) = tokio::runtime::current_thread::block_on_all(
                fetch_eth1_data(distance, current_block_number, self.fetcher.clone()),
            )
            .ok()?
            {
                let mut cache_write = self.cache.write();
                cache_write.insert(block_number, eth1_data);
                return Some(cache_write.get(&block_number)?.clone());
            }
        }
        None
    }

    /// Returns a Vec<Eth1Data> corresponding to given distance range.
    pub fn get_eth1_data_in_range(&mut self, start: u64, end: u64) -> Vec<Eth1Data> {
        (start..end)
            .map(|h| self.get_eth1_data(h))
            .flatten() // Chuck None values. This might be okay since its unlikely that the entire range returns None.
            .collect::<Vec<Eth1Data>>()
    }
}

fn fetch_eth1_data_in_range<F: Eth1DataFetcher>(
    start: u64,
    end: u64,
    current_block_number: U256,
    fetcher: Arc<F>,
) -> impl Stream<Item = Result<(U256, Eth1Data), Eth1Error>, Error = Eth1Error> + Send {
    stream::futures_ordered(
        (start..end).map(move |i| fetch_eth1_data(i, current_block_number, fetcher.clone())),
    )
}

/// Fetches Eth1 data from the Eth1Data fetcher object.
fn fetch_eth1_data<F: Eth1DataFetcher>(
    distance: u64,
    current_block_number: U256,
    fetcher: Arc<F>,
) -> impl Future<Item = Result<(U256, Eth1Data), Eth1Error>, Error = Eth1Error> + Send {
    let block_number: U256 = current_block_number
        .checked_sub(distance.into())
        .unwrap_or(U256::zero());
    let deposit_root = fetcher.get_deposit_root(Some(BlockNumber::Number(block_number.as_u64())));
    let deposit_count = fetcher.get_deposit_count(Some(BlockNumber::Number(block_number.as_u64())));
    let block_hash = fetcher.get_block_hash_by_height(block_number.as_u64());
    let eth1_data_future = deposit_root.join3(deposit_count, block_hash);
    eth1_data_future.map(move |data| {
        let eth1_data = Eth1Data {
            deposit_root: data.0,
            deposit_count: data.1?,
            block_hash: data.2.ok_or(Eth1Error::DecodingError)?,
        };
        Ok((block_number, eth1_data))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContractConfig;
    use crate::web3_fetcher::Web3DataFetcher;
    use std::time::{Duration, Instant};
    use tokio::timer::{Delay, Interval};
    use web3::types::Address;

    // Note: Running tests using ganache-cli instance with config
    // from https://github.com/ChainSafe/lodestar#starting-private-eth1-chain

    fn setup() -> Web3DataFetcher {
        let deposit_contract_address: Address =
            "8c594691C0E592FFA21F153a16aE41db5beFcaaa".parse().unwrap();
        let deposit_contract = ContractConfig {
            address: deposit_contract_address,
            abi: include_bytes!("deposit_contract.json").to_vec(),
        };
        let w3 = Web3DataFetcher::new("ws://localhost:8545", deposit_contract);
        return w3;
    }

    #[test]
    fn test_fetch() {
        let w3 = setup();
        let when = Instant::now() + Duration::from_millis(5000);
        let task1 = Delay::new(when)
            .and_then(|_| {
                println!("Hello world!");
                Ok(())
            })
            .map_err(|e| panic!("delay errored; err={:?}", e));
        tokio::run(task1);
        let task2 = fetch_eth1_data(0, 10.into(), Arc::new(w3)).and_then(|data| {
            println!("{:?}", data);
            Ok(())
        });
        tokio::run(task2.map_err(|e| println!("Some error {:?}", e)));
    }

    #[test]
    fn test_cache() {
        let w3 = setup();
        let interval = {
            let update_duration = Duration::from_secs(15);
            Interval::new(Instant::now(), update_duration).map_err(|e| println!("{:?}", e))
        };

        let cache = Eth1DataCache::new(Arc::new(w3));
        let cache_inside = cache.cache.clone();
        let task = interval.take(100).for_each(move |_| {
            let c = cache_inside.clone();
            cache
                .update_cache(3 + 1)
                .and_then(move |_| Ok(()))
                .map_err(|e| println!("Some error {:?}", e))
        });
        tokio::run(task.map_err(|e| println!("Some error {:?}", e)));
    }
}
