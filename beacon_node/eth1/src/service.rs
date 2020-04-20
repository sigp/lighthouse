use crate::metrics;
use crate::{
    block_cache::{BlockCache, Error as BlockCacheError, Eth1Block},
    deposit_cache::Error as DepositCacheError,
    http::{get_block, get_block_number, get_deposit_logs_in_range},
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

const STANDARD_TIMEOUT_MILLIS: u64 = 15_000;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getLogs to read the deposit contract logs.
const GET_DEPOSIT_LOG_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// The remote node is less synced that we expect, it is not useful until has done more
    /// syncing.
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
    FailedToParseDepositLog {
        block_range: Range<u64>,
        error: String,
    },
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
    ///
    /// Note: this should be less than or equal to the specification's `ETH1_FOLLOW_DISTANCE`.
    pub follow_distance: u64,
    /// Defines the number of blocks that should be retained each time the `BlockCache` calls truncate on
    /// itself.
    pub block_cache_truncation: Option<usize>,
    /// The interval between updates when using the `auto_update` function.
    pub auto_update_interval_millis: u64,
    /// The span of blocks we should query for logs, per request.
    pub blocks_per_log_query: usize,
    /// The maximum number of log requests per update.
    pub max_log_requests_per_update: Option<usize>,
    /// The maximum number of log requests per update.
    pub max_blocks_per_update: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8545".into(),
            deposit_contract_address: "0x0000000000000000000000000000000000000000".into(),
            deposit_contract_deploy_block: 1,
            lowest_cached_block_number: 1,
            follow_distance: 128,
            block_cache_truncation: Some(4_096),
            auto_update_interval_millis: 7_000,
            blocks_per_log_query: 1_000,
            max_log_requests_per_update: None,
            max_blocks_per_update: None,
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
                deposit_cache: RwLock::new(DepositUpdater::new(
                    config.deposit_contract_deploy_block,
                )),
                config: RwLock::new(config),
                ..Inner::default()
            }),
            log,
        }
    }

    /// Return byte representation of deposit and block caches.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes()
    }

    /// Recover the deposit and block caches from encoded bytes.
    pub fn from_bytes(bytes: &[u8], config: Config, log: Logger) -> Result<Self, String> {
        let inner = Inner::from_bytes(bytes, config)?;
        Ok(Self {
            inner: Arc::new(inner),
            log,
        })
    }

    /// Provides access to the block cache.
    pub fn blocks(&self) -> &RwLock<BlockCache> {
        &self.inner.block_cache
    }

    /// Provides access to the deposit cache.
    pub fn deposits(&self) -> &RwLock<DepositUpdater> {
        &self.inner.deposit_cache
    }

    /// Drop the block cache, replacing it with an empty one.
    pub fn drop_block_cache(&self) {
        *(self.inner.block_cache.write()) = BlockCache::default();
    }

    /// Returns the timestamp of the earliest block in the cache (if any).
    pub fn earliest_block_timestamp(&self) -> Option<u64> {
        self.inner.block_cache.read().earliest_block_timestamp()
    }

    /// Returns the timestamp of the latest block in the cache (if any).
    pub fn latest_block_timestamp(&self) -> Option<u64> {
        self.inner.block_cache.read().latest_block_timestamp()
    }

    /// Returns the lowest block number stored.
    pub fn lowest_block_number(&self) -> Option<u64> {
        self.inner.block_cache.read().lowest_block_number()
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

    /// Updates the configuration in `self to be `new_config`.
    ///
    /// Will truncate the block cache if the new configure specifies truncation.
    pub fn update_config(&self, new_config: Config) -> Result<(), String> {
        let mut old_config = self.inner.config.write();

        if new_config.deposit_contract_deploy_block != old_config.deposit_contract_deploy_block {
            // This may be possible, I just haven't looked into the details to ensure it's safe.
            Err("Updating deposit_contract_deploy_block is not supported".to_string())
        } else {
            *old_config = new_config;

            // Prevents a locking condition when calling prune_blocks.
            drop(old_config);

            self.inner.prune_blocks();

            Ok(())
        }
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
        let inner_1 = self.inner.clone();
        let inner_2 = self.inner.clone();

        let deposit_future = self
            .update_deposit_cache()
            .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))
            .then(move |result| {
                match &result {
                    Ok(DepositCacheUpdateOutcome::Success { logs_imported }) => trace!(
                        log_a,
                        "Updated eth1 deposit cache";
                        "cached_deposits" => inner_1.deposit_cache.read().cache.len(),
                        "logs_imported" => logs_imported,
                        "last_processed_eth1_block" => inner_1.deposit_cache.read().last_processed_block,
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
                        "cached_blocks" => inner_2.block_cache.read().len(),
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

    /// A looping future that updates the cache, then waits `config.auto_update_interval` before
    /// updating it again.
    ///
    /// ## Returns
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub fn auto_update(&self, exit: Exit) -> impl Future<Item = (), Error = ()> {
        let service = self.clone();
        let log = self.log.clone();
        let update_interval = Duration::from_millis(self.config().auto_update_interval_millis);

        let loop_future = loop_fn((), move |()| {
            let service = service.clone();
            let log_a = log.clone();
            let log_b = log.clone();

            service
                .update()
                .then(move |update_result| {
                    match update_result {
                        Err(e) => error!(
                            log_a,
                            "Failed to update eth1 cache";
                            "retry_millis" => update_interval.as_millis(),
                            "error" => e,
                        ),
                        Ok((deposit, block)) => debug!(
                            log_a,
                            "Updated eth1 cache";
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
                    Ok(Loop::Continue(()))
                })
        });

        exit.until(loop_future).map(|_: Option<()>| ())
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
        let blocks_per_log_query = self.config().blocks_per_log_query;
        let max_log_requests_per_update = self
            .config()
            .max_log_requests_per_update
            .unwrap_or_else(usize::max_value);

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
        .map(move |range| {
            range
                .map(|range| {
                    range
                        .collect::<Vec<u64>>()
                        .chunks(blocks_per_log_query)
                        .take(max_log_requests_per_update)
                        .map(|vec| {
                            let first = vec.first().cloned().unwrap_or_else(|| 0);
                            let last = vec.last().map(|n| n + 1).unwrap_or_else(|| 0);
                            first..last
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
                            .map_err(Error::GetDepositLogsFailed)
                            .map(|logs| (chunk_1, logs))
                            .map(|logs| (logs, chunks)),
                        )
                    }
                    None => None,
                },
            )
            .fold(0, move |mut sum, (block_range, log_chunk)| {
                let mut cache = service_2.deposits().write();

                log_chunk
                    .into_iter()
                    .map(|raw_log| {
                        DepositLog::from_log(&raw_log).map_err(|error| {
                            Error::FailedToParseDepositLog {
                                block_range: block_range.clone(),
                                error,
                            }
                        })
                    })
                    // Return early if any of the logs cannot be parsed.
                    //
                    // This costs an additional `collect`, however it enforces that no logs are
                    // imported if any one of them cannot be parsed.
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|deposit_log| {
                        cache
                            .cache
                            .insert_log(deposit_log)
                            .map_err(Error::FailedToInsertDeposit)?;

                        sum += 1;

                        Ok(())
                    })
                    // Returns if a deposit is unable to be added to the cache.
                    //
                    // If this error occurs, the cache will no longer be guaranteed to hold either
                    // none or all of the logs for each block (i.e., they may exist _some_ logs for
                    // a block, but not _all_ logs for that block). This scenario can cause the
                    // node to choose an invalid genesis state or propose an invalid block.
                    .collect::<Result<_, _>>()?;

                cache.last_processed_block = Some(block_range.end.saturating_sub(1));

                metrics::set_gauge(&metrics::DEPOSIT_CACHE_LEN, cache.cache.len() as i64);
                metrics::set_gauge(
                    &metrics::HIGHEST_PROCESSED_DEPOSIT_BLOCK,
                    cache.last_processed_block.unwrap_or_else(|| 0) as i64,
                );

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
        let cache_6 = self.inner.clone();

        let block_cache_truncation = self.config().block_cache_truncation;
        let max_blocks_per_update = self
            .config()
            .max_blocks_per_update
            .unwrap_or_else(usize::max_value);

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
                        // Note: this check is not strictly necessary, however it remains to safe
                        // guard against any regression which may cause an underflow in a following
                        // subtraction operation.
                        Err(Error::Internal("Range was not increasing".into()))
                    } else {
                        let range_size = range.end() - range.start();
                        let max_size = block_cache_truncation
                            .map(|n| n as u64)
                            .unwrap_or_else(u64::max_value);
                        if range_size > max_size {
                            // If the range of required blocks is larger than `max_size`, drop all
                            // existing blocks and download `max_size` count of blocks.
                            let first_block = range.end() - max_size;
                            (*cache_5.block_cache.write()) = BlockCache::default();
                            Ok((first_block..=*range.end()).collect::<Vec<u64>>())
                        } else {
                            Ok(range.collect::<Vec<u64>>())
                        }
                    }
                })
                .unwrap_or_else(|| Ok(vec![]))
        })
        // Download the range of blocks and sequentially import them into the cache.
        .and_then(move |required_block_numbers| {
            // Last processed block in deposit cache
            let latest_in_cache = cache_6
                .deposit_cache
                .read()
                .last_processed_block
                .unwrap_or(0);

            let required_block_numbers = required_block_numbers
                .into_iter()
                .filter(|x| *x <= latest_in_cache)
                .take(max_blocks_per_update)
                .collect::<Vec<_>>();
            // Produce a stream from the list of required block numbers and return a future that
            // consumes the it.
            stream::unfold(
                required_block_numbers.into_iter(),
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
                    .map_err(Error::FailedToInsertEth1Block)?;

                metrics::set_gauge(
                    &metrics::BLOCK_CACHE_LEN,
                    cache_3.block_cache.read().len() as i64,
                );
                metrics::set_gauge(
                    &metrics::LATEST_CACHED_BLOCK_TIMESTAMP,
                    cache_3
                        .block_cache
                        .read()
                        .latest_block_timestamp()
                        .unwrap_or_else(|| 0) as i64,
                );

                Ok(sum + 1)
            })
        })
        .and_then(move |blocks_imported| {
            // Prune the block cache, preventing it from growing too large.
            cache_4.prune_blocks();

            metrics::set_gauge(
                &metrics::BLOCK_CACHE_LEN,
                cache_4.block_cache.read().len() as i64,
            );

            Ok(BlockCacheUpdateOutcome::Success {
                blocks_imported,
                head_block_number: cache_4.block_cache.read().highest_block_number(),
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
        .map_err(Error::GetBlockNumberFailed)
        .and_then(move |remote_highest_block| {
            let remote_follow_block = remote_highest_block.saturating_sub(follow_distance);

            if next_required_block <= remote_follow_block {
                Ok(Some(next_required_block..=remote_follow_block))
            } else if next_required_block > remote_highest_block + 1 {
                // If this is the case, the node must have gone "backwards" in terms of it's sync
                // (i.e., it's head block is lower than it was before).
                //
                // We assume that the `follow_distance` should be sufficient to ensure this never
                // happens, otherwise it is an error.
                Err(Error::RemoteNotSynced {
                    next_required_block,
                    remote_highest_block,
                    follow_distance,
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
    let deposit_root = cache
        .deposit_cache
        .read()
        .cache
        .get_deposit_root_from_cache(block_number);
    let deposit_count = cache
        .deposit_cache
        .read()
        .cache
        .get_deposit_count_from_cache(block_number);
    // Performs a `get_blockByNumber` call to an eth1 node.
    get_block(
        &cache.config.read().endpoint,
        block_number,
        Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
    )
    .map_err(Error::BlockDownloadFailed)
    .map(move |http_block| Eth1Block {
        hash: http_block.hash,
        number: http_block.number,
        timestamp: http_block.timestamp,
        deposit_root,
        deposit_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use toml;

    #[test]
    fn serde_serialize() {
        let serialized =
            toml::to_string(&Config::default()).expect("Should serde encode default config");
        toml::from_str::<Config>(&serialized).expect("Should serde decode default config");
    }
}
