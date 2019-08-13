use crate::types::Eth1DataFetcher;
use std::collections::BTreeMap;
use std::sync::Arc;
use types::*;
use web3::types::*;

/// Cache for recent Eth1Data fetched from the Eth1 chain.
#[derive(Clone, Debug)]
pub struct Eth1DataCache<F: Eth1DataFetcher> {
    cache: BTreeMap<U256, Eth1Data>,
    last_block: u64,
    fetcher: Arc<F>,
}

impl<F: Eth1DataFetcher> Eth1DataCache<F> {
    pub fn new(fetcher: Arc<F>) -> Self {
        Eth1DataCache {
            cache: BTreeMap::new(),
            // Should ideally start from block where Eth1 chain starts accepting deposits.
            last_block: 0,
            fetcher,
        }
    }

    /// Called periodically to populate the cache with Eth1Data from most recent blocks.
    pub fn update_cache(&mut self) -> Option<()> {
        let current_block_number: U256 = self.fetcher.get_current_block_number()?;
        for i in self.last_block..current_block_number.as_u64() {
            if !self.cache.contains_key(&U256::from(i)) {
                if let Some((block_number, data)) = self.fetch_eth1_data(i, current_block_number) {
                    self.cache.insert(block_number, data);
                }
            }
        }
        self.last_block = current_block_number.as_u64();
        // TODO: Delete older stuff in a fifo order.
        Some(())
    }

    /// Get `Eth1Data` object at a distance of `distance` from the perceived head of the currrent Eth1 chain.
    /// Returns the object from the cache if present, else fetches from Eth1Fetcher.
    pub fn get_eth1_data(&mut self, distance: u64) -> Option<Eth1Data> {
        let current_block_number: U256 = self.fetcher.get_current_block_number()?;
        let block_number: U256 = current_block_number.checked_sub(distance.into())?;
        if self.cache.contains_key(&block_number) {
            return Some(self.cache.get(&block_number)?.clone());
        } else {
            if let Some((block_number, eth1_data)) =
                self.fetch_eth1_data(distance, current_block_number)
            {
                self.cache.insert(block_number, eth1_data);
                return Some(self.cache.get(&block_number)?.clone());
            }
        }
        None
    }

    /// Returns a Vec<Eth1Data> corresponding to given distance range.
    pub fn get_eth1_data_in_range(&mut self, start: u64, end: u64) -> Vec<Eth1Data> {
        (start..end)
            .map(|h| self.get_eth1_data(h))
            .flatten() // Chuck None values
            .collect::<Vec<Eth1Data>>()
    }

    /// Fetches Eth1 data from the Eth1Data fetcher object.
    fn fetch_eth1_data(
        &self,
        distance: u64,
        current_block_number: U256,
    ) -> Option<(U256, Eth1Data)> {
        let block_number: U256 = current_block_number.checked_sub(distance.into())?;
        Some((
            block_number,
            Eth1Data {
                deposit_root: self
                    .fetcher
                    .get_deposit_root(Some(BlockNumber::Number(block_number.as_u64())))?,
                deposit_count: self
                    .fetcher
                    .get_deposit_count(Some(BlockNumber::Number(block_number.as_u64())))?,
                block_hash: self
                    .fetcher
                    .get_block_hash_by_height(block_number.as_u64())?,
            },
        ))
    }
}
