use crate::block_cache::{BlockCache, Error as BlockCacheError};
use crate::deposit_cache::{DepositCache, DepositLog, Error as DepositCacheError};
use crate::http::{
    get_block, get_block_number, get_deposit_count, get_deposit_logs_in_range, get_deposit_root,
    Block,
};
use futures::{prelude::*, stream, Future};
use parking_lot::RwLock;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use types::Hash256;

const BLOCKS_PER_LOG_QUERY: usize = 10;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_call to read the deposit contract root.
const GET_DEPOSIT_ROOT_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_call to read the deposit contract deposit count.
const GET_DEPOSIT_COUNT_TIMEOUT_MILLIS: u64 = 1_000;
/// Timeout when doing an eth_getLogs to read the deposit contract logs.
const GET_DEPOSIT_LOG_TIMEOUT_MILLIS: u64 = 1_000;

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
    FailedToInsertEth1Snapshot(BlockCacheError),
    NodeUnableToSyncDeposits {
        remote_head_block: u64,
        last_processed_block: u64,
    },
    FailedToInsertDeposit(DepositCacheError),
    IncompleteLogResponse {
        expected: usize,
        response: usize,
    },
    GetDepositLogsFailed(String),
    FailedToParseDepositLog {
        block_range: Range<u64>,
        error: String,
    },
    Internal(String),
}

/// The success message for an Eth1Data cache update.
#[derive(Debug, PartialEq, Clone)]
pub enum Eth1UpdateResult {
    /// The cache was sucessfully updated.
    Success {
        blocks_imported: usize,
        head_block_number: u64,
    },
}

/// The success message for an Eth1 deposit cache update.
#[derive(Debug, PartialEq, Clone)]
pub enum DepositCacheUpdateResult {
    /// The cache was sucessfully updated.
    Success { logs_imported: usize },
}

/// The preferred method for instantiating an `Eth1Cache`.
pub struct Eth1CacheBuilder {
    endpoint: String,
    deposit_contract_address: String,
    initial_eth1_block: u64,
    eth1_follow_distance: u64,
    target_block_cache_len: usize,
    deposit_log_start_block: u64,
}

impl Eth1CacheBuilder {
    /// Creates a new builder with defaults.
    pub fn new(endpoint: String, deposit_contract_address: String) -> Self {
        Self {
            endpoint,
            deposit_contract_address,
            initial_eth1_block: 128,
            eth1_follow_distance: 0,
            target_block_cache_len: 2_048,
            deposit_log_start_block: 0,
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
    /// Setting the value to `0` means we follow the head.
    ///
    /// Default `128`.
    pub fn eth1_follow_distance(mut self, eth1_follow_distance: u64) -> Self {
        self.eth1_follow_distance = eth1_follow_distance;
        self
    }

    /// Defines how many blocks to store in the cache, prior to the `eth1_follow_distance`.
    ///
    /// Sometimes the cache may grow larger than this, but it will generally be kept at this size.
    ///
    /// Default `2_048`.
    pub fn target_block_cache_len(mut self, len: usize) -> Self {
        self.target_block_cache_len = len;
        self
    }

    /// Sets the block that the deposit contract was deployed at. The cache will not search for
    /// deposit logs any earlier than this block.
    ///
    /// Setting this too low will result in unnecessarily scanning blocks that will definitely not
    /// have any useful information. Setting it too high will result in missing deposit logs.
    ///
    /// Default `0`.
    pub fn deposit_contract_deploy_block(mut self, block_number: u64) -> Self {
        self.deposit_log_start_block = block_number;
        self
    }

    /// Consumers the builder and returns a new `Eth1Cache`.
    pub fn build(self) -> Eth1Cache {
        Eth1Cache {
            endpoint: self.endpoint,
            deposit_contract_address: self.deposit_contract_address,
            block_cache: RwLock::new(BlockCache::new(self.initial_eth1_block as usize)),
            follow_distance: self.eth1_follow_distance,
            target_block_cache_len: self.target_block_cache_len,
            deposit_cache: RwLock::new(DepositUpdater {
                cache: DepositCache::new(),
                last_processed_block: self.deposit_log_start_block,
            }),
        }
    }
}

struct DepositUpdater {
    cache: DepositCache,
    last_processed_block: u64,
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
    target_block_cache_len: usize,
    /// Stores the deposit cache and the block number that was the subject of the last update.
    deposit_cache: RwLock<DepositUpdater>,
}

impl Eth1Cache {
    /// Returns the block number of the latest block in the `Eth1Data` cache.
    pub fn latest_block_number(&self) -> Option<u64> {
        self.block_cache
            .read()
            .available_block_numbers()
            .map(|r| *r.end())
    }

    /// Prunes the block cache to `self.target_block_cache_len`.
    fn prune_blocks(&self) {
        self.block_cache
            .write()
            .truncate(self.target_block_cache_len);
    }

    /// Returns the number of currently cached blocks.
    pub fn block_cache_len(&self) -> usize {
        self.block_cache.read().len()
    }
}

pub fn update_deposit_cache<'a>(
    cache: Arc<Eth1Cache>,
) -> impl Future<Item = DepositCacheUpdateResult, Error = Error> + 'a + Send {
    let cache_1 = cache.clone();
    let cache_2 = cache.clone();

    get_block_number(
        &cache.endpoint,
        Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS),
    )
    .map_err(|e| Error::GetBlockNumberFailed(e))
    .and_then(move |remote_head_block| {
        let last_processed_block = cache.deposit_cache.read().last_processed_block;

        if remote_head_block < last_processed_block {
            Err(Error::NodeUnableToSyncDeposits {
                remote_head_block,
                last_processed_block,
            })
        } else {
            Ok(last_processed_block + 1..remote_head_block + 1)
        }
    })
    .map(|entire_block_range| {
        entire_block_range
            .into_iter()
            .collect::<Vec<u64>>()
            .chunks(BLOCKS_PER_LOG_QUERY)
            .map(|vec| {
                let first = vec.first().cloned().unwrap_or_else(|| 0);
                let last = vec.last().cloned().map(|n| n + 1).unwrap_or_else(|| 0);
                (first..last)
            })
            .collect::<Vec<Range<u64>>>()
    })
    .and_then(move |block_number_chunks| {
        stream::unfold(
            block_number_chunks.into_iter(),
            move |mut chunks| match chunks.next() {
                Some(chunk) => {
                    let chunk_1 = chunk.clone();
                    Some(
                        get_deposit_logs_in_range(
                            &cache_1.endpoint,
                            &cache_1.deposit_contract_address,
                            chunk,
                            Duration::from_millis(GET_DEPOSIT_LOG_TIMEOUT_MILLIS),
                        )
                        .map_err(|e| Error::GetDepositLogsFailed(e))
                        .map(|logs| (chunk_1, logs))
                        .map(|logs| (logs, chunks)),
                    )
                }
                None => None,
            },
        )
        .fold(0, move |sum, (block_range, log_chunk)| {
            let block_range_1 = block_range.clone();

            let count = log_chunk.into_iter().try_fold(0, |count, raw_log| {
                let block_range = block_range.clone();

                let deposit_log = DepositLog::from_log(&raw_log)
                    .map_err(|error| Error::FailedToParseDepositLog { block_range, error })?;

                cache_2
                    .deposit_cache
                    .write()
                    .cache
                    .insert_log(deposit_log)
                    .map_err(|e| Error::FailedToInsertDeposit(e))?;

                Ok(count + 1)
            })?;

            cache_2.deposit_cache.write().last_processed_block =
                block_range_1.end.saturating_sub(1);

            Ok(sum + count)
        })
        .map(|logs_imported| DepositCacheUpdateResult::Success { logs_imported })
    })

    // TODO: update the last processed block.
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
    let cache_5 = cache.clone();

    get_block_number(
        &cache.endpoint,
        Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS),
    )
    .map_err(|e| Error::GetBlockNumberFailed(e))
    // Determine the range of blocks that need to be downloaded, given the remotes best block and
    // the locally stored best block.
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
    // Inspect the range of blocks and determine if they are bigger than the current cache size.
    //
    // There is no need to download more than the cache size of blocks. Instead, it is more
    // efficient to completely drop the cache and fill it up again.
    .and_then(move |range| {
        if range.start > range.end {
            Err(Error::Internal("Range was not increasing".into()))
        } else {
            let range_size = range.end - range.start;
            let max_size = cache_5.target_block_cache_len as u64;

            if range_size > max_size {
                let first_block = range.end - max_size;
                (*cache_5.block_cache.write()) = BlockCache::new(first_block as usize);
                Ok(first_block..range.end)
            } else {
                Ok(range)
            }
        }
    })
    // Download the range of blocks and sequentially import them into the cache.
    .and_then(|required_block_numbers| {
        // Never download more blocks than can fit in the block cache.
        let required_block_numbers = required_block_numbers
            .into_iter()
            .take(cache_3.target_block_cache_len);

        // Produce a stream from the list of required block numbers and return a future that
        // consumes the it.
        stream::unfold(
            required_block_numbers,
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
        // Prune the block cache, preventing it from growing too large.
        cache_4.prune_blocks();

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
