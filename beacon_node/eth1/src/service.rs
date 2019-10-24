use crate::{
    block_cache::{BlockCache, Error as BlockCacheError, Eth1Block},
    deposit_cache::Error as DepositCacheError,
    http::{
        get_block, get_block_number, get_deposit_count, get_deposit_logs_in_range, get_deposit_root,
    },
    inner::{DepositUpdater, Inner},
    DepositLog,
};
use exit_future::Exit;
use futures::{
    future::{loop_fn, Loop},
    stream, Future, Stream,
};
use parking_lot::{RwLock, RwLockReadGuard};
use serde::{Deserialize, Serialize};
use slog::{debug, error, trace, Logger};
use std::ops::{Range, RangeInclusive};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Delay;

/// The span of blocks we should query for logs, per request.
const BLOCKS_PER_LOG_QUERY: usize = 1_000;
/// The maximum number of log requests per update.
const MAX_LOG_REQUESTS_PER_UPDATE: usize = 1;

/// The maximum number of log requests per update.
const MAX_BLOCKS_PER_UPDATE: usize = 1;

const STANDARD_TIMEOUT_MILLIS: u64 = 15_000;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_call to read the deposit contract root.
const GET_DEPOSIT_ROOT_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_call to read the deposit contract deposit count.
const GET_DEPOSIT_COUNT_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getLogs to read the deposit contract logs.
const GET_DEPOSIT_LOG_TIMEOUT_MILLIS: u64 = 15_000;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// The remote node is less synced that we expect.
    RemoteNotSynced {
        next_required_block: u64,
        remote_highest_block: u64,
        follow_distance: u64,
    },
    /// Failed to download a block from the eth1 node.
    BlockDownloadFailed(String),
    /// Failed to get the current block number from the eth1 node.
    GetBlockNumberFailed(String),
    /// Failed to read the deposit contract root from the eth1 node.
    GetDepositRootFailed(String),
    /// Failed to read the deposit contract deposit count from the eth1 node.
    GetDepositCountFailed(String),
    /// Failed to read the deposit contract root from the eth1 node.
    GetDepositLogsFailed(String),
    /// There was an inconsistency when adding a block to the cache.
    FailedToInsertEth1Block(BlockCacheError),
    /// There was an inconsistency when adding a deposit to the cache.
    FailedToInsertDeposit(DepositCacheError),
    /// A log downloaded from the eth1 contract was not well formed.
    IncompleteLogResponse { expected: usize, response: usize },
    /// A log downloaded from the eth1 contract was not well formed.
    FailedToParseDepositLog {
        block_range: Range<u64>,
        error: String,
    },
    /// The eth1 http json-rpc node returned an error.
    Eth1RpcError(String),
    /// There was an unexpected internal error.
    Internal(String),
}

/// The success message for an Eth1Data cache update.
#[derive(Debug, PartialEq, Clone)]
pub enum BlockCacheUpdateOutcome {
    /// The cache was sucessfully updated.
    Success {
        blocks_imported: usize,
        head_block_number: Option<u64>,
    },
}

/// The success message for an Eth1 deposit cache update.
#[derive(Debug, PartialEq, Clone)]
pub enum DepositCacheUpdateOutcome {
    /// The cache was sucessfully updated.
    Success { logs_imported: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// An Eth1 node (e.g., Geth) running a HTTP JSON-RPC endpoint.
    pub endpoint: String,
    /// The address the `BlockCache` and `DepositCache` should assume is the canonical deposit contract.
    pub deposit_contract_address: String,
    /// Defines the first block that the `DepositCache` will start searching for deposit logs.
    ///
    /// Setting too high can result in missed logs. Setting too low will result in unnecessary
    /// calls to the Eth1 node's HTTP JSON RPC.
    pub deposit_contract_deploy_block: u64,
    /// Defines the lowest block number that should be downloaded and added to the `BlockCache`.
    pub lowest_cached_block_number: u64,
    /// Defines how far behind the Eth1 node's head we should follow.
    pub follow_distance: u64,
    /// Defines the number of blocks that should be retained each time the `BlockCache` calls truncate on
    /// itself.
    pub block_cache_truncation: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8545".into(),
            deposit_contract_address: "0x0000000000000000000000000000000000000000".into(),
            deposit_contract_deploy_block: 0,
            lowest_cached_block_number: 0,
            follow_distance: 128,
            block_cache_truncation: Some(4_096),
        }
    }
}

/// Provides a set of Eth1 caches and async functions to update them.
///
/// Stores the following caches:
///
/// - Deposit cache: stores all deposit logs from the deposit contract.
/// - Block cache: stores some number of eth1 blocks.
#[derive(Clone)]
pub struct Service {
    inner: Arc<Inner>,
    pub log: Logger,
}

impl Service {
    /// Creates a new service. Does not attempt to connect to the eth1 node.
    pub fn new(config: Config, log: Logger) -> Self {
        Self {
            inner: Arc::new(Inner {
                config: RwLock::new(config),
                ..Inner::default()
            }),
            log,
        }
    }

    /// Provides access to the block cache.
    pub fn blocks(&self) -> &RwLock<BlockCache> {
        &self.inner.block_cache
    }

    /// Provides access to the deposit cache.
    pub fn deposits(&self) -> &RwLock<DepositUpdater> {
        &self.inner.deposit_cache
    }

    /// Returns the number of currently cached blocks.
    pub fn block_cache_len(&self) -> usize {
        self.blocks().read().len()
    }

    /// Returns the number deposits available in the deposit cache.
    pub fn deposit_cache_len(&self) -> usize {
        self.deposits().read().cache.len()
    }

    /// Read the service's configuration.
    pub fn config(&self) -> RwLockReadGuard<Config> {
        self.inner.config.read()
    }

    /// Set the lowest block that the block cache will store.
    ///
    /// Note: this block may not always be present if truncating is enabled.
    pub fn set_lowest_cached_block(&self, block_number: u64) {
        self.inner.config.write().lowest_cached_block_number = block_number;
    }

    /// Update the deposit and block cache, returning an error if either fail.
    ///
    /// ## Returns
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub fn update(
        &self,
    ) -> impl Future<Item = (DepositCacheUpdateOutcome, BlockCacheUpdateOutcome), Error = String>
    {
        let log_a = self.log.clone();
        let log_b = self.log.clone();

        let deposit_future = self
            .update_deposit_cache()
            .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))
            .then(move |result| {
                match &result {
                    Ok(DepositCacheUpdateOutcome::Success { logs_imported }) => trace!(
                        log_a,
                        "Updated eth1 deposit cache";
                        "logs_imported" => logs_imported,
                    ),
                    Err(e) => error!(
                        log_a,
                        "Failed to update eth1 deposit cache";
                        "error" => e
                    ),
                };

                result
            });

        let block_future = self
            .update_block_cache()
            .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))
            .then(move |result| {
                match &result {
                    Ok(BlockCacheUpdateOutcome::Success {
                        blocks_imported,
                        head_block_number,
                    }) => trace!(
                        log_b,
                        "Updated eth1 block cache";
                        "blocks_imported" => blocks_imported,
                        "head_block" => head_block_number,
                    ),
                    Err(e) => error!(
                        log_b,
                        "Failed to update eth1 block cache";
                        "error" => e
                    ),
                };

                result
            });

        deposit_future.join(block_future)
    }

    /// A looping future that updates the cache, then waits `update_interval` before updating it
    /// again.
    ///
    /// ## Returns
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub fn auto_update(
        &self,
        update_interval: Duration,
        exit_signal: Exit,
    ) -> impl Future<Item = (), Error = ()> {
        let service = self.clone();
        let log = self.log.clone();

        loop_fn((), move |()| {
            let exit_signal = exit_signal.clone();
            let service = service.clone();
            let log_a = log.clone();
            let log_b = log.clone();

            service
                .update()
                .then(move |update_result| {
                    match update_result {
                        Err(e) => error!(
                            log_a,
                            "Failed to update eth1 genesis cache";
                            "retry_millis" => update_interval.as_millis(),
                            "error" => e,
                        ),
                        Ok((deposit, block)) => debug!(
                            log_a,
                            "Updated eth1 genesis cache";
                            "retry_millis" => update_interval.as_millis(),
                            "blocks" => format!("{:?}", block),
                            "deposits" => format!("{:?}", deposit),
                        ),
                    };

                    // Do not break the loop if there is an update failure.
                    Ok(())
                })
                .and_then(move |_| Delay::new(Instant::now() + update_interval))
                .then(move |timer_result| {
                    if let Err(e) = timer_result {
                        error!(
                            log_b,
                            "Failed to trigger eth1 cache update delay";
                            "error" => format!("{:?}", e),
                        );
                    }
                    // Do not break the loop if there is an timer failure.
                    Ok(())
                })
                .map(move |_| {
                    if exit_signal.is_live() {
                        Loop::Continue(())
                    } else {
                        Loop::Break(())
                    }
                })
        })
    }

    /// Contacts the remote eth1 node and attempts to import deposit logs up to the configured
    /// follow-distance block.
    ///
    /// Will process no more than `BLOCKS_PER_LOG_QUERY * MAX_LOG_REQUESTS_PER_UPDATE` blocks in a
    /// single update.
    ///
    /// ## Resolves with
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub fn update_deposit_cache(
        &self,
    ) -> impl Future<Item = DepositCacheUpdateOutcome, Error = Error> {
        let service_1 = self.clone();
        let service_2 = self.clone();

        let next_required_block = self
            .deposits()
            .read()
            .last_processed_block
            .map(|n| n + 1)
            .unwrap_or_else(|| self.config().deposit_contract_deploy_block);

        get_new_block_numbers(
            &self.config().endpoint,
            next_required_block,
            self.config().follow_distance,
        )
        .map(|range| {
            range
                .map(|range| {
                    range
                        .into_iter()
                        .collect::<Vec<u64>>()
                        .chunks(BLOCKS_PER_LOG_QUERY)
                        .take(MAX_LOG_REQUESTS_PER_UPDATE)
                        .map(|vec| {
                            let first = vec.first().cloned().unwrap_or_else(|| 0);
                            let last = vec.last().map(|n| n + 1).unwrap_or_else(|| 0);
                            (first..last)
                        })
                        .collect::<Vec<Range<u64>>>()
                })
                .unwrap_or_else(|| vec![])
        })
        .and_then(move |block_number_chunks| {
            stream::unfold(
                block_number_chunks.into_iter(),
                move |mut chunks| match chunks.next() {
                    Some(chunk) => {
                        let chunk_1 = chunk.clone();
                        Some(
                            get_deposit_logs_in_range(
                                &service_1.config().endpoint,
                                &service_1.config().deposit_contract_address,
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
            .fold(0, move |mut sum, (block_range, log_chunk)| {
                // It's important that blocks are log are imported atomically per-block, unless an
                // error occurs. There is no guarantee for consistency if an error is returned.
                //
                // That is, if there are any logs from block `n`, then there are _all_ logs
                // from block `n` and all prior blocks.
                //
                // This is achieved by taking an exclusive write-lock on the cache whilst adding
                // logs one-by-one.
                let mut cache = service_2.deposits().write();

                for raw_log in log_chunk {
                    let deposit_log = DepositLog::from_log(&raw_log).map_err(|error| {
                        Error::FailedToParseDepositLog {
                            block_range: block_range.clone(),
                            error,
                        }
                    })?;

                    cache
                        .cache
                        .insert_log(deposit_log)
                        .map_err(|e| Error::FailedToInsertDeposit(e))?;

                    sum += 1;
                }

                cache.last_processed_block = Some(block_range.end.saturating_sub(1));

                Ok(sum)
            })
            .map(|logs_imported| DepositCacheUpdateOutcome::Success { logs_imported })
        })
    }

    /// Contacts the remote eth1 node and attempts to import all blocks up to the configured
    /// follow-distance block.
    ///
    /// If configured, prunes the block cache after importing new blocks.
    ///
    /// ## Resolves with
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub fn update_block_cache(&self) -> impl Future<Item = BlockCacheUpdateOutcome, Error = Error> {
        let cache_1 = self.inner.clone();
        let cache_2 = self.inner.clone();
        let cache_3 = self.inner.clone();
        let cache_4 = self.inner.clone();
        let cache_5 = self.inner.clone();

        let block_cache_truncation = self.inner.config.read().block_cache_truncation;

        let next_required_block = cache_1
            .block_cache
            .read()
            .highest_block_number()
            .map(|n| n + 1)
            .unwrap_or_else(|| self.config().lowest_cached_block_number);

        get_new_block_numbers(
            &self.config().endpoint,
            next_required_block,
            self.config().follow_distance,
        )
        // Map the range of required blocks into a Vec.
        //
        // If the required range is larger than the size of the cache, drop the exiting cache
        // because it's exipred and just download enough blocks to fill the cache.
        .and_then(move |range| {
            range
                .map(|range| {
                    if range.start() > range.end() {
                        Err(Error::Internal("Range was not increasing".into()))
                    } else {
                        let range_size = range.end() - range.start();
                        let max_size = block_cache_truncation
                            .map(|n| n as u64)
                            .unwrap_or_else(|| u64::max_value());

                        if range_size > max_size {
                            let first_block = range.end() - max_size;
                            (*cache_5.block_cache.write()) = BlockCache::default();
                            Ok((first_block..=*range.end())
                                .into_iter()
                                .collect::<Vec<u64>>())
                        } else {
                            Ok(range.into_iter().collect::<Vec<u64>>())
                        }
                    }
                })
                .unwrap_or_else(|| Ok(vec![]))
        })
        // Download the range of blocks and sequentially import them into the cache.
        .and_then(move |required_block_numbers| {
            let required_block_numbers = required_block_numbers
                .into_iter()
                .take(MAX_BLOCKS_PER_UPDATE);

            // Produce a stream from the list of required block numbers and return a future that
            // consumes the it.
            stream::unfold(
                required_block_numbers,
                move |mut block_numbers| match block_numbers.next() {
                    Some(block_number) => Some(
                        download_eth1_block(cache_2.clone(), block_number)
                            .map(|v| (v, block_numbers)),
                    ),
                    None => None,
                },
            )
            .fold(0, move |sum, eth1_block| {
                cache_3
                    .block_cache
                    .write()
                    .insert_root_or_child(eth1_block)
                    .map_err(|e| Error::FailedToInsertEth1Block(e))?;

                Ok(sum + 1)
            })
        })
        .and_then(move |blocks_imported| {
            // Prune the block cache, preventing it from growing too large.
            cache_4.prune_blocks();

            Ok(BlockCacheUpdateOutcome::Success {
                blocks_imported,
                head_block_number: cache_4.clone().block_cache.read().highest_block_number(),
            })
        })
    }
}

/// Determine the range of blocks that need to be downloaded, given the remotes best block and
/// the locally stored best block.
fn get_new_block_numbers<'a>(
    endpoint: &str,
    next_required_block: u64,
    follow_distance: u64,
) -> impl Future<Item = Option<RangeInclusive<u64>>, Error = Error> + 'a {
    get_block_number(endpoint, Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS))
        .map_err(|e| Error::GetBlockNumberFailed(e))
        .and_then(move |remote_highest_block| {
            let remote_follow_block = remote_highest_block.saturating_sub(follow_distance);

            if next_required_block <= remote_follow_block {
                // Plus one to make the range inclusive.
                Ok(Some(next_required_block..=remote_follow_block))
            } else if next_required_block > remote_highest_block + 1 {
                Err(Error::RemoteNotSynced {
                    next_required_block,
                    remote_highest_block,
                    follow_distance: follow_distance,
                })
            } else {
                // Return an empty range.
                Ok(None)
            }
        })
}

/// Downloads the `(block, deposit_root, deposit_count)` tuple from an eth1 node for the given
/// `block_number`.
///
/// Performs three async calls to an Eth1 HTTP JSON RPC endpoint.
fn download_eth1_block<'a>(
    cache: Arc<Inner>,
    block_number: u64,
) -> impl Future<Item = Eth1Block, Error = Error> + 'a {
    // Performs a `get_blockByNumber` call to an eth1 node.
    get_block(
        &cache.config.read().endpoint,
        block_number,
        Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
    )
    .map_err(|e| Error::BlockDownloadFailed(e))
    .join3(
        // Perform 2x `eth_call` via an eth1 node to read the deposit contract root and count.
        get_deposit_root(
            &cache.config.read().endpoint,
            &cache.config.read().deposit_contract_address,
            block_number,
            Duration::from_millis(GET_DEPOSIT_ROOT_TIMEOUT_MILLIS),
        )
        .map_err(|e| Error::GetDepositRootFailed(e)),
        get_deposit_count(
            &cache.config.read().endpoint,
            &cache.config.read().deposit_contract_address,
            block_number,
            Duration::from_millis(GET_DEPOSIT_COUNT_TIMEOUT_MILLIS),
        )
        .map_err(|e| Error::GetDepositCountFailed(e)),
    )
    .map(|(http_block, deposit_root, deposit_count)| Eth1Block {
        hash: http_block.hash,
        number: http_block.number,
        timestamp: http_block.timestamp,
        deposit_root,
        deposit_count,
    })
}
