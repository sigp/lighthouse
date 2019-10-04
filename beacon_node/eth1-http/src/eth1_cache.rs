use crate::block_cache::{BlockCache, Error as Eth1Error};
use crate::http::{get_block, get_block_number, get_deposit_count, get_deposit_root, Block};
use futures::{prelude::*, stream, Future};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use types::Hash256;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_call to read the deposit contract root.
const GET_DEPOSIT_ROOT_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_call to read the deposit contract deposit count.
const GET_DEPOSIT_COUNT_TIMEOUT_MILLIS: u64 = 1_000;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    RemoteNotSynced {
        local_highest_block: u64,
        remote_highest_block: u64,
        follow_distance: u64,
    },
    BlockDownloadFailed(String),
    GetBlockNumberFailed(String),
    GetDepositRootFailed(String),
    GetDepositCountFailed(String),
    FailedToInsertEth1Snapshot(Eth1Error),
}

/// The success message for an Eth1 cache update.
#[derive(Debug, PartialEq, Clone)]
pub enum Eth1UpdateResult {
    /// The Eth1 cache was sucessfully updated.
    Success {
        blocks_imported: usize,
        head_block_number: u64,
    },
}

/// The preferred method for instantiating an `Eth1Cache`.
pub struct Eth1CacheBuilder {
    endpoint: String,
    deposit_contract_address: String,
    initial_eth1_block: u64,
    eth1_follow_distance: u64,
}

impl Eth1CacheBuilder {
    /// Creates a new builder with defaults.
    pub fn new(endpoint: String, deposit_contract_address: String) -> Self {
        Self {
            endpoint,
            deposit_contract_address,
            initial_eth1_block: 128,
            eth1_follow_distance: 0,
        }
    }

    /// Sets the earliest block that will be downloaded to satisfy the `Eth1Data` cache.
    ///
    /// Failing to set this away from the default of `0` may result in the entire eth1 chain being
    /// downloaded and stored in memory.
    pub fn initial_eth1_block(mut self, initial_eth1_block: u64) -> Self {
        self.initial_eth1_block = initial_eth1_block;
        self
    }

    /// Sets the follow distance for the caches.
    ///
    /// Setting the value higher means waiting for more confirmations before importing Eth1 data.
    /// Setting the value to `0` means we follow the head. The default is `128`.
    pub fn eth1_follow_distance(mut self, eth1_follow_distance: u64) -> Self {
        self.eth1_follow_distance = eth1_follow_distance;
        self
    }

    /// Consumers the builder and returns a new `Eth1Cache`.
    pub fn build(self) -> Eth1Cache {
        Eth1Cache {
            endpoint: self.endpoint,
            deposit_contract_address: self.deposit_contract_address,
            block_cache: RwLock::new(BlockCache::new(self.initial_eth1_block as usize)),
            follow_distance: self.eth1_follow_distance,
        }
    }
}

/// Stores all necessary information for beacon chain block production, including choosing an
/// `Eth1Data` for block production and gathering `Deposits` for inclusion in blocks.
///
/// Thread-safe and async.
pub struct Eth1Cache {
    endpoint: String,
    deposit_contract_address: String,
    block_cache: RwLock<BlockCache>,
    follow_distance: u64,
}

impl Eth1Cache {
    /// Returns the block number of the latest block in the `Eth1Data` cache.
    pub fn latest_block_number(&self) -> Option<u64> {
        self.block_cache
            .read()
            .available_block_numbers()
            .map(|r| *r.end())
    }
}

/// Try and perform an update on the cache, doing nothing if it's already in the process of an
/// update.
pub fn update_block_cache<'a>(
    cache: Arc<Eth1Cache>,
) -> impl Future<Item = Eth1UpdateResult, Error = Error> + 'a + Send {
    let cache_1 = cache.clone();
    let cache_2 = cache.clone();
    let cache_3 = cache.clone();
    let cache_4 = cache.clone();

    get_block_number(
        &cache.endpoint,
        Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS),
    )
    .map_err(|e| Error::GetBlockNumberFailed(e))
    .and_then(move |remote_highest_block| {
        let local_highest_block: u64 = cache_1
            .block_cache
            .read()
            .available_block_numbers()
            .map(|range| *range.end())
            .unwrap_or_else(|| cache_1.block_cache.read().next_block_number());

        let remote_follow_block = remote_highest_block.saturating_sub(cache.follow_distance);

        if local_highest_block <= remote_follow_block {
            let first_block: u64 = cache_1
                .block_cache
                .read()
                .available_block_numbers()
                .map(|range| *range.end() + 1)
                .unwrap_or_else(|| cache_1.block_cache.read().next_block_number());

            // Plus one to make the range inclusive.
            Ok(first_block..remote_follow_block + 1)
        } else {
            if local_highest_block > remote_highest_block {
                Err(Error::RemoteNotSynced {
                    local_highest_block,
                    remote_highest_block,
                    follow_distance: cache_1.follow_distance,
                })
            } else {
                // An empty range is a no-op.
                Ok(0..0)
            }
        }
    })
    .and_then(|required_block_numbers| {
        // Produce a stream from the list of required block numbers and return a future that
        // consumes the it.
        stream::unfold(
            required_block_numbers.into_iter(),
            move |mut block_numbers| match block_numbers.next() {
                Some(block_number) => Some(
                    download_eth1_snapshot(cache_2.clone(), block_number)
                        .map(|v| (v, block_numbers)),
                ),
                None => None,
            },
        )
        .filter_map(|snapshot| snapshot)
        .fold(0, move |sum, (block, deposit_root, deposit_count)| {
            cache_3
                .block_cache
                .write()
                .insert(block, deposit_root, deposit_count)
                .map_err(|e| Error::FailedToInsertEth1Snapshot(e))?;
            Ok(sum + 1)
        })
    })
    .and_then(move |blocks_imported| {
        Ok(Eth1UpdateResult::Success {
            blocks_imported,
            head_block_number: cache_4
                .clone()
                .block_cache
                .read()
                .next_block_number()
                .saturating_sub(1),
        })
    })
}

/// Downloads the `(block, deposit_root, deposit_count)` tuple from an eth1 node for the given
/// `block_number`.
///
/// Performs three async calls to an Eth1 HTTP JSON RPC endpoint.
fn download_eth1_snapshot<'a>(
    cache: Arc<Eth1Cache>,
    block_number: u64,
) -> impl Future<Item = Option<(Block, Hash256, u64)>, Error = Error> + 'a {
    // Performs a `get_blockByNumber` call to an eth1 node.
    get_block(
        &cache.endpoint,
        block_number,
        Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
    )
    .map_err(|e| Error::BlockDownloadFailed(e))
    .join3(
        // Perform 2x `eth_call` via an eth1 node to read the deposit contract root and count.
        get_deposit_root(
            &cache.endpoint,
            &cache.deposit_contract_address,
            block_number,
            Duration::from_millis(GET_DEPOSIT_ROOT_TIMEOUT_MILLIS),
        )
        .map_err(|e| Error::GetDepositRootFailed(e)),
        get_deposit_count(
            &cache.endpoint,
            &cache.deposit_contract_address,
            block_number,
            Duration::from_millis(GET_DEPOSIT_COUNT_TIMEOUT_MILLIS),
        )
        .map_err(|e| Error::GetDepositCountFailed(e)),
    )
    .map(|snapshot| {
        // Assume that a missing deposit root or count indicates that this block is prior to the
        // deployment of the Eth1 contract and is therefore invalid.
        if let (block, Some(deposit_root), Some(deposit_count)) = snapshot {
            Some((block, deposit_root, deposit_count))
        } else {
            None
        }
    })
}
