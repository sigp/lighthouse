use crate::metrics;
use crate::{
    block_cache::{BlockCache, Error as BlockCacheError, Eth1Block},
    deposit_cache::Error as DepositCacheError,
    http::{
        get_block, get_block_number, get_deposit_logs_in_range, get_network_id, Eth1NetworkId, Log,
    },
    inner::{DepositUpdater, Inner},
    DepositLog,
};
use futures::{future::TryFutureExt, stream, stream::TryStreamExt, StreamExt};
use parking_lot::{RwLock, RwLockReadGuard};
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, Logger};
use std::ops::{Range, RangeInclusive};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{interval_at, Duration, Instant};
use types::ChainSpec;

/// Indicates the default eth1 network we use for the deposit contract.
pub const DEFAULT_NETWORK_ID: Eth1NetworkId = Eth1NetworkId::Goerli;

const STANDARD_TIMEOUT_MILLIS: u64 = 15_000;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getLogs to read the deposit contract logs.
const GET_DEPOSIT_LOG_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;

const WARNING_MSG: &str = "BLOCK PROPOSALS WILL FAIL WITHOUT VALID ETH1 CONNECTION";

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
pub struct BlockCacheUpdateOutcome {
    pub blocks_imported: usize,
    pub head_block_number: Option<u64>,
}

/// The success message for an Eth1 deposit cache update.
#[derive(Debug, PartialEq, Clone)]
pub struct DepositCacheUpdateOutcome {
    pub logs_imported: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// An Eth1 node (e.g., Geth) running a HTTP JSON-RPC endpoint.
    pub endpoint: String,
    /// The address the `BlockCache` and `DepositCache` should assume is the canonical deposit contract.
    pub deposit_contract_address: String,
    /// The eth1 network id where the deposit contract is deployed (Goerli/Mainnet).
    pub network_id: Eth1NetworkId,
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
            network_id: DEFAULT_NETWORK_ID,
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
    pub fn new(config: Config, log: Logger, spec: ChainSpec) -> Self {
        Self {
            inner: Arc::new(Inner {
                block_cache: <_>::default(),
                deposit_cache: RwLock::new(DepositUpdater::new(
                    config.deposit_contract_deploy_block,
                )),
                config: RwLock::new(config),
                spec,
            }),
            log,
        }
    }

    /// Return byte representation of deposit and block caches.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes()
    }

    /// Recover the deposit and block caches from encoded bytes.
    pub fn from_bytes(
        bytes: &[u8],
        config: Config,
        log: Logger,
        spec: ChainSpec,
    ) -> Result<Self, String> {
        let inner = Inner::from_bytes(bytes, config, spec)?;
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

    /// Removes all blocks from the cache, except for the latest block.
    ///
    /// We don't remove the latest blocks so we don't lose track of the latest block.
    pub fn clear_block_cache(&self) {
        self.inner.block_cache.write().truncate(1)
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

    /// Returns the highest block that is present in both the deposit and block caches.
    pub fn highest_safe_block(&self) -> Option<u64> {
        let block_cache = self.blocks().read().highest_block_number()?;
        let deposit_cache = self.deposits().read().last_processed_block?;

        Some(std::cmp::min(block_cache, deposit_cache))
    }

    /// Returns the number of currently cached blocks.
    pub fn block_cache_len(&self) -> usize {
        self.blocks().read().len()
    }

    /// Returns the number deposits available in the deposit cache.
    pub fn deposit_cache_len(&self) -> usize {
        self.deposits().read().cache.len()
    }

    /// Returns the number of deposits with valid signatures that have been observed.
    pub fn get_valid_signature_count(&self) -> Option<usize> {
        self.deposits()
            .read()
            .cache
            .get_valid_signature_count(self.highest_safe_block()?)
    }

    /// Returns the number of deposits with valid signatures that have been observed, without
    /// respecting the `highest_safe_block`.
    pub fn get_raw_valid_signature_count(&self) -> Option<usize> {
        let deposits = self.deposits().read();
        deposits
            .cache
            .get_valid_signature_count(deposits.cache.latest_block_number()?)
    }

    /// Returns the number of deposits with valid signatures that have been observed up to and
    /// including the block at `block_number`.
    ///
    /// Returns `None` if the `block_number` is zero or prior to contract deployment.
    pub fn get_valid_signature_count_at_block(&self, block_number: u64) -> Option<usize> {
        self.deposits()
            .read()
            .cache
            .get_valid_signature_count(block_number)
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
    pub async fn update(
        &self,
    ) -> Result<(DepositCacheUpdateOutcome, BlockCacheUpdateOutcome), String> {
        let update_deposit_cache = async {
            let outcome = self
                .update_deposit_cache()
                .await
                .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))?;

            trace!(
                self.log,
                "Updated eth1 deposit cache";
                "cached_deposits" => self.inner.deposit_cache.read().cache.len(),
                "logs_imported" => outcome.logs_imported,
                "last_processed_eth1_block" => self.inner.deposit_cache.read().last_processed_block,
            );
            Ok(outcome)
        };

        let update_block_cache = async {
            let outcome = self
                .update_block_cache()
                .await
                .map_err(|e| format!("Failed to update eth1 cache: {:?}", e))?;

            trace!(
                self.log,
                "Updated eth1 block cache";
                "cached_blocks" => self.inner.block_cache.read().len(),
                "blocks_imported" => outcome.blocks_imported,
                "head_block" => outcome.head_block_number,
            );
            Ok(outcome)
        };

        futures::try_join!(update_deposit_cache, update_block_cache)
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
    pub fn auto_update(self, handle: environment::TaskExecutor) {
        let update_interval = Duration::from_millis(self.config().auto_update_interval_millis);

        let mut interval = interval_at(Instant::now(), update_interval);

        let update_future = async move {
            while interval.next().await.is_some() {
                self.do_update(update_interval).await.ok();
            }
        };

        handle.spawn(update_future, "eth1");
    }

    async fn do_update(&self, update_interval: Duration) -> Result<(), ()> {
        let endpoint = self.config().endpoint.clone();
        let config_network = self.config().network_id.clone();
        let result =
            get_network_id(&endpoint, Duration::from_millis(STANDARD_TIMEOUT_MILLIS)).await;
        match result {
            Ok(network_id) => {
                if network_id != config_network {
                    crit!(
                        self.log,
                        "Invalid eth1 network. Please switch to correct network";
                        "expected" => format!("{:?}",DEFAULT_NETWORK_ID),
                        "received" => format!("{:?}",network_id),
                        "warning" => WARNING_MSG,
                    );
                    return Ok(());
                }
            }
            Err(_) => {
                crit!(
                    self.log,
                    "Error connecting to eth1 node. Please ensure that you have an eth1 http server running locally on http://localhost:8545 or \
                    pass an external endpoint using `--eth1-endpoint <SERVER-ADDRESS>`. Also ensure that `eth` and `net` apis are enabled on the eth1 http server";
                    "warning" => WARNING_MSG,
                );
                return Ok(());
            }
        }

        let update_result = self.update().await;
        match update_result {
            Err(e) => error!(
                self.log,
                "Failed to update eth1 cache";
                "retry_millis" => update_interval.as_millis(),
                "error" => e,
            ),
            Ok((deposit, block)) => debug!(
                self.log,
                "Updated eth1 cache";
                "retry_millis" => update_interval.as_millis(),
                "blocks" => format!("{:?}", block),
                "deposits" => format!("{:?}", deposit),
            ),
        };
        Ok(())
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
    pub async fn update_deposit_cache(&self) -> Result<DepositCacheUpdateOutcome, Error> {
        let endpoint = self.config().endpoint.clone();
        let follow_distance = self.config().follow_distance;
        let deposit_contract_address = self.config().deposit_contract_address.clone();

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

        let range = get_new_block_numbers(&endpoint, next_required_block, follow_distance).await?;

        let block_number_chunks = if let Some(range) = range {
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
        } else {
            Vec::new()
        };

        let logs: Vec<(Range<u64>, Vec<Log>)> =
            stream::try_unfold(block_number_chunks.into_iter(), |mut chunks| async {
                match chunks.next() {
                    Some(chunk) => {
                        let chunk_1 = chunk.clone();
                        match get_deposit_logs_in_range(
                            &endpoint,
                            &deposit_contract_address,
                            chunk,
                            Duration::from_millis(GET_DEPOSIT_LOG_TIMEOUT_MILLIS),
                        )
                        .await
                        {
                            Ok(logs) => Ok(Some(((chunk_1, logs), chunks))),
                            Err(e) => Err(Error::GetDepositLogsFailed(e)),
                        }
                    }
                    None => Ok(None),
                }
            })
            .try_collect()
            .await?;

        let mut logs_imported = 0;
        for (block_range, log_chunk) in logs.iter() {
            let mut cache = self.deposits().write();
            log_chunk
                .iter()
                .map(|raw_log| {
                    DepositLog::from_log(&raw_log, self.inner.spec()).map_err(|error| {
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

                    logs_imported += 1;

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
        }

        if logs_imported > 0 {
            info!(
                self.log,
                "Imported deposit log(s)";
                "latest_block" => self.inner.deposit_cache.read().cache.latest_block_number(),
                "total" => self.deposit_cache_len(),
                "new" => logs_imported
            );
        } else {
            debug!(
                self.log,
                "No new deposits found";
                "latest_block" => self.inner.deposit_cache.read().cache.latest_block_number(),
                "total_deposits" => self.deposit_cache_len(),
            );
        }

        Ok(DepositCacheUpdateOutcome { logs_imported })
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
    pub async fn update_block_cache(&self) -> Result<BlockCacheUpdateOutcome, Error> {
        let block_cache_truncation = self.config().block_cache_truncation;
        let max_blocks_per_update = self
            .config()
            .max_blocks_per_update
            .unwrap_or_else(usize::max_value);

        let next_required_block = self
            .inner
            .block_cache
            .read()
            .highest_block_number()
            .map(|n| n + 1)
            .unwrap_or_else(|| self.config().lowest_cached_block_number);

        let endpoint = self.config().endpoint.clone();
        let follow_distance = self.config().follow_distance;

        let range = get_new_block_numbers(&endpoint, next_required_block, follow_distance).await?;
        // Map the range of required blocks into a Vec.
        //
        // If the required range is larger than the size of the cache, drop the exiting cache
        // because it's exipred and just download enough blocks to fill the cache.
        let required_block_numbers = if let Some(range) = range {
            if range.start() > range.end() {
                // Note: this check is not strictly necessary, however it remains to safe
                // guard against any regression which may cause an underflow in a following
                // subtraction operation.
                return Err(Error::Internal("Range was not increasing".into()));
            } else {
                let range_size = range.end() - range.start();
                let max_size = block_cache_truncation
                    .map(|n| n as u64)
                    .unwrap_or_else(u64::max_value);
                if range_size > max_size {
                    // If the range of required blocks is larger than `max_size`, drop all
                    // existing blocks and download `max_size` count of blocks.
                    let first_block = range.end() - max_size;
                    (*self.inner.block_cache.write()) = BlockCache::default();
                    (first_block..=*range.end()).collect::<Vec<u64>>()
                } else {
                    range.collect::<Vec<u64>>()
                }
            }
        } else {
            Vec::new()
        };
        // Download the range of blocks and sequentially import them into the cache.
        // Last processed block in deposit cache
        let latest_in_cache = self
            .inner
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

        let eth1_blocks: Vec<Eth1Block> = stream::try_unfold(
            required_block_numbers.into_iter(),
            |mut block_numbers| async {
                match block_numbers.next() {
                    Some(block_number) => {
                        match download_eth1_block(self.inner.clone(), block_number).await {
                            Ok(eth1_block) => Ok(Some((eth1_block, block_numbers))),
                            Err(e) => Err(e),
                        }
                    }
                    None => Ok(None),
                }
            },
        )
        .try_collect()
        .await?;

        let mut blocks_imported = 0;
        for eth1_block in eth1_blocks {
            self.inner
                .block_cache
                .write()
                .insert_root_or_child(eth1_block)
                .map_err(Error::FailedToInsertEth1Block)?;

            metrics::set_gauge(
                &metrics::BLOCK_CACHE_LEN,
                self.inner.block_cache.read().len() as i64,
            );
            metrics::set_gauge(
                &metrics::LATEST_CACHED_BLOCK_TIMESTAMP,
                self.inner
                    .block_cache
                    .read()
                    .latest_block_timestamp()
                    .unwrap_or_else(|| 0) as i64,
            );

            blocks_imported += 1;
        }

        // Prune the block cache, preventing it from growing too large.
        self.inner.prune_blocks();

        metrics::set_gauge(
            &metrics::BLOCK_CACHE_LEN,
            self.inner.block_cache.read().len() as i64,
        );

        let block_cache = self.inner.block_cache.read();
        let latest_block_mins = block_cache
            .latest_block_timestamp()
            .and_then(|timestamp| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|now| now.checked_sub(Duration::from_secs(timestamp)))
            })
            .map(|duration| format!("{} mins", duration.as_secs() / 60))
            .unwrap_or_else(|| "n/a".into());

        if blocks_imported > 0 {
            debug!(
                self.log,
                "Imported eth1 block(s)";
                "latest_block_age" => latest_block_mins,
                "latest_block" => block_cache.highest_block_number(),
                "total_cached_blocks" => block_cache.len(),
                "new" => blocks_imported
            );
        } else {
            debug!(
                self.log,
                "No new eth1 blocks imported";
                "latest_block" => block_cache.highest_block_number(),
                "cached_blocks" => block_cache.len(),
            );
        }

        Ok(BlockCacheUpdateOutcome {
            blocks_imported,
            head_block_number: self.inner.block_cache.read().highest_block_number(),
        })
    }
}

/// Determine the range of blocks that need to be downloaded, given the remotes best block and
/// the locally stored best block.
async fn get_new_block_numbers<'a>(
    endpoint: &str,
    next_required_block: u64,
    follow_distance: u64,
) -> Result<Option<RangeInclusive<u64>>, Error> {
    let remote_highest_block =
        get_block_number(endpoint, Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS))
            .map_err(Error::GetBlockNumberFailed)
            .await?;
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
}

/// Downloads the `(block, deposit_root, deposit_count)` tuple from an eth1 node for the given
/// `block_number`.
///
/// Performs three async calls to an Eth1 HTTP JSON RPC endpoint.
async fn download_eth1_block(cache: Arc<Inner>, block_number: u64) -> Result<Eth1Block, Error> {
    let endpoint = cache.config.read().endpoint.clone();

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
    let http_block = get_block(
        &endpoint,
        block_number,
        Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
    )
    .map_err(Error::BlockDownloadFailed)
    .await?;

    Ok(Eth1Block {
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
