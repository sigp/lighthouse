use crate::fetcher::Eth1DataFetcher;
use std::collections::BTreeMap;
use types::*;
use web3::types::*;

const START: u64 = 1024;
const END: u64 = 3072;

/// Cache for recent Eth1Data fetched from the Eth1 chain.
pub struct Eth1DataCache {
    cache: BTreeMap<U256, Eth1Data>,
}

impl Eth1DataCache {
    pub fn new() -> Self {
        Eth1DataCache {
            cache: BTreeMap::new(),
        }
    }

    /// Called periodically to populate the cache with Eth1Data from most recent blocks.
    pub fn update_cache<T: Eth1DataFetcher>(&mut self, eth1_fetcher: &T) -> Option<()> {
        let current_block_number: U256 = eth1_fetcher.get_current_block_number()?;
        for i in START..END {
            if !self.cache.contains_key(&U256::from(i)) {
                if let Some((block_number, data)) =
                    fetch_eth1_data(i, current_block_number, eth1_fetcher)
                {
                    self.cache.insert(block_number, data);
                }
            }
        }
        // TODO: Delete older stuff
        Some(())
    }

    /// Get `Eth1Data` object at a distance of `distance` from the perceived head of the currrent Eth1 chain.
    /// Returns the object from the cache if present, else fetches from Eth1Fetcher.
    pub fn get_eth1_data<T: Eth1DataFetcher>(
        &mut self,
        distance: u64,
        eth1_fetcher: &T,
    ) -> Option<Eth1Data> {
        let current_block_number: U256 = eth1_fetcher.get_current_block_number()?;
        let block_number: U256 = current_block_number.checked_sub(distance.into())?;
        if self.cache.contains_key(&block_number) {
            return Some(self.cache.get(&block_number)?.clone());
        } else {
            if let Some((block_number, eth1_data)) =
                fetch_eth1_data(distance, current_block_number, eth1_fetcher)
            {
                self.cache.insert(block_number, eth1_data);
                return Some(self.cache.get(&block_number)?.clone());
            }
        }
        None
    }

    /// Returns a Vec<Eth1Data> corresponding to given distance range.
    pub fn get_eth1_data_in_range<T: Eth1DataFetcher>(
        &mut self,
        eth1_fetcher: &T,
        start: u64,
        end: u64,
    ) -> Vec<Eth1Data> {
        (start..end)
            .map(|h| self.get_eth1_data::<T>(h, &eth1_fetcher))
            .flatten()
            .collect::<Vec<Eth1Data>>()
    }
}

/// Fetches Eth1 data from the Eth1Data fetcher object.
pub fn fetch_eth1_data<T: Eth1DataFetcher>(
    distance: u64,
    current_block_number: U256,
    eth1_fetcher: &T,
) -> Option<(U256, Eth1Data)> {
    let block_number: U256 = current_block_number.checked_sub(distance.into())?;
    Some((
        block_number,
        Eth1Data {
            deposit_root: eth1_fetcher
                .get_deposit_root(Some(BlockNumber::Number(block_number.as_u64())))?,
            deposit_count: eth1_fetcher
                .get_deposit_count(Some(BlockNumber::Number(block_number.as_u64())))?,
            block_hash: eth1_fetcher.get_block_hash_by_height(block_number.as_u64())?,
        },
    ))
}
