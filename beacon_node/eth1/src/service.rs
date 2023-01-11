use crate::metrics;
use crate::{
    block_cache::{BlockCache, Error as BlockCacheError, Eth1Block},
    deposit_cache::{DepositCacheInsertOutcome, Error as DepositCacheError},
    inner::{DepositUpdater, Inner},
};
use execution_layer::auth::Auth;
use execution_layer::http::{
    deposit_methods::{BlockQuery, Eth1Id},
    HttpJsonRpc,
};
use futures::future::TryFutureExt;
use parking_lot::{RwLock, RwLockReadGuard};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, trace, warn, Logger};
use std::fmt::Debug;
use std::ops::{Range, RangeInclusive};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{interval_at, Duration, Instant};
use types::{ChainSpec, DepositTreeSnapshot, Eth1Data, EthSpec, Unsigned};

/// Indicates the default eth1 chain id we use for the deposit contract.
pub const DEFAULT_CHAIN_ID: Eth1Id = Eth1Id::Goerli;
/// Indicates the default eth1 endpoint.
pub const DEFAULT_ETH1_ENDPOINT: &str = "http://localhost:8545";

const STANDARD_TIMEOUT_MILLIS: u64 = 15_000;

/// Timeout when doing a eth_blockNumber call.
const BLOCK_NUMBER_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getBlockByNumber call.
const GET_BLOCK_TIMEOUT_MILLIS: u64 = STANDARD_TIMEOUT_MILLIS;
/// Timeout when doing an eth_getLogs to read the deposit contract logs.
const GET_DEPOSIT_LOG_TIMEOUT_MILLIS: u64 = 60_000;

/// Number of blocks to download if the node detects it is lagging behind due to an inaccurate
/// relationship between block-number-based follow distance and time-based follow distance.
const CATCHUP_BATCH_SIZE: u64 = 128;

/// The absolute minimum follow distance to enforce when downloading catchup batches.
const CATCHUP_MIN_FOLLOW_DISTANCE: u64 = 64;

/// To account for fast PoW blocks requiring more blocks in the cache than the block-based follow
/// distance would imply, we store `CACHE_FACTOR` more blocks in our cache.
const CACHE_FACTOR: u64 = 2;

#[derive(Debug, PartialEq, Clone)]
pub enum EndpointError {
    RequestFailed(String),
    WrongChainId,
    FarBehind,
}

type EndpointState = Result<(), EndpointError>;

/// Returns `Ok` if the endpoint is usable, i.e. is reachable and has a correct network id and
/// chain id. Otherwise it returns `Err`.
async fn endpoint_state(
    endpoint: &HttpJsonRpc,
    config_chain_id: &Eth1Id,
    log: &Logger,
) -> EndpointState {
    let error_connecting = |e: String| {
        debug!(
            log,
            "eth1 endpoint error";
            "endpoint" => %endpoint,
            "error" => &e,
        );
        warn!(
            log,
            "Error connecting to eth1 node endpoint";
            "endpoint" => %endpoint,
        );
        EndpointError::RequestFailed(e)
    };

    let chain_id = endpoint
        .get_chain_id(Duration::from_millis(STANDARD_TIMEOUT_MILLIS))
        .await
        .map_err(error_connecting)?;
    // Eth1 nodes return chain_id = 0 if the node is not synced
    // Handle the special case
    if chain_id == Eth1Id::Custom(0) {
        warn!(
            log,
            "Remote execution node is not synced";
            "endpoint" => %endpoint,
        );
        return Err(EndpointError::FarBehind);
    }
    if &chain_id != config_chain_id {
        warn!(
            log,
            "Invalid execution chain ID. Please switch to correct chain ID on endpoint";
            "endpoint" => %endpoint,
            "expected" => ?config_chain_id,
            "received" => ?chain_id,
        );
        Err(EndpointError::WrongChainId)
    } else {
        Ok(())
    }
}

/// Enum for the two internal (maybe different) cached heads for cached deposits and for the block
/// cache.
pub enum HeadType {
    Deposit,
    BlockCache,
}

/// Returns the head block and the new block ranges relevant for deposits and the block cache
/// from the given endpoint.
async fn get_remote_head_and_new_block_ranges(
    endpoint: &HttpJsonRpc,
    service: &Service,
    node_far_behind_seconds: u64,
) -> Result<
    (
        Eth1Block,
        Option<RangeInclusive<u64>>,
        Option<RangeInclusive<u64>>,
    ),
    Error,
> {
    let remote_head_block = download_eth1_block(endpoint, service.inner.clone(), None).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    if remote_head_block.timestamp + node_far_behind_seconds < now {
        warn!(
            service.log,
            "Execution endpoint is not synced";
            "endpoint" => %endpoint,
            "last_seen_block_unix_timestamp" => remote_head_block.timestamp,
        );
        return Err(Error::EndpointError(EndpointError::FarBehind));
    }

    let handle_remote_not_synced = |e| {
        if let Error::RemoteNotSynced { .. } = e {
            warn!(
                service.log,
                "Execution endpoint is not synced";
                "endpoint" => %endpoint,
            );
        }
        e
    };
    let new_deposit_block_numbers = service
        .relevant_new_block_numbers(
            remote_head_block.number,
            Some(remote_head_block.timestamp),
            HeadType::Deposit,
        )
        .map_err(handle_remote_not_synced)?;
    let new_block_cache_numbers = service
        .relevant_new_block_numbers(
            remote_head_block.number,
            Some(remote_head_block.timestamp),
            HeadType::BlockCache,
        )
        .map_err(handle_remote_not_synced)?;
    Ok((
        remote_head_block,
        new_deposit_block_numbers,
        new_block_cache_numbers,
    ))
}

/// Returns the range of new block numbers to be considered for the given head type from the given
/// endpoint.
async fn relevant_new_block_numbers_from_endpoint(
    endpoint: &HttpJsonRpc,
    service: &Service,
    head_type: HeadType,
) -> Result<Option<RangeInclusive<u64>>, Error> {
    let remote_highest_block = endpoint
        .get_block_number(Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS))
        .map_err(Error::GetBlockNumberFailed)
        .await?;
    service.relevant_new_block_numbers(remote_highest_block, None, head_type)
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// There was an inconsistency when adding a block to the cache.
    FailedToInsertEth1Block(BlockCacheError),
    /// There was an inconsistency when adding a deposit to the cache.
    FailedToInsertDeposit(DepositCacheError),
    /// A log downloaded from the eth1 contract was not well formed.
    FailedToParseDepositLog {
        block_range: Range<u64>,
        error: String,
    },
    /// Endpoint is currently not functional.
    EndpointError(EndpointError),
    /// The remote node is less synced that we expect, it is not useful until has done more
    /// syncing.
    RemoteNotSynced {
        next_required_block: u64,
        remote_highest_block: u64,
        cache_follow_distance: u64,
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
    /// There was an unexpected internal error.
    Internal(String),
    /// Error finalizing deposit
    FailedToFinalizeDeposit(String),
    /// There was a problem Initializing from deposit snapshot
    FailedToInitializeFromSnapshot(String),
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

/// Supports either one authenticated jwt JSON-RPC endpoint **or**
/// multiple non-authenticated endpoints with fallback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Eth1Endpoint {
    Auth {
        endpoint: SensitiveUrl,
        jwt_path: PathBuf,
        jwt_id: Option<String>,
        jwt_version: Option<String>,
    },
    NoAuth(SensitiveUrl),
}

impl Eth1Endpoint {
    pub fn get_endpoint(&self) -> SensitiveUrl {
        match &self {
            Self::Auth { endpoint, .. } => endpoint.clone(),
            Self::NoAuth(endpoint) => endpoint.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// An Eth1 node (e.g., Geth) running a HTTP JSON-RPC endpoint.
    pub endpoint: Eth1Endpoint,
    /// The address the `BlockCache` and `DepositCache` should assume is the canonical deposit contract.
    pub deposit_contract_address: String,
    /// The eth1 chain id where the deposit contract is deployed (Goerli/Mainnet).
    pub chain_id: Eth1Id,
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
    /// The follow distance to use for blocks in our cache.
    ///
    /// This can be set lower than the true follow distance in order to correct for poor timing
    /// of eth1 blocks.
    pub cache_follow_distance: Option<u64>,
    /// Specifies the seconds when we consider the head of a node far behind.
    /// This should be less than `ETH1_FOLLOW_DISTANCE * SECONDS_PER_ETH1_BLOCK`.
    pub node_far_behind_seconds: u64,
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
    /// If set to true, the eth1 caches are wiped clean when the eth1 service starts.
    pub purge_cache: bool,
    pub execution_timeout_multiplier: u32,
}

impl Config {
    /// Sets the block cache to a length that is suitable for the given `EthSpec` and `ChainSpec`.
    pub fn set_block_cache_truncation<E: EthSpec>(&mut self, spec: &ChainSpec) {
        // Compute the number of eth1 blocks in an eth1 voting period.
        let seconds_per_voting_period =
            E::SlotsPerEth1VotingPeriod::to_u64() * spec.seconds_per_slot;
        let eth1_blocks_per_voting_period = seconds_per_voting_period / spec.seconds_per_eth1_block;

        // Ensure we can store two full windows of voting blocks.
        let voting_windows = eth1_blocks_per_voting_period * 2;

        // Extend the cache to account for the cache follow distance.
        let extra_follow_distance_blocks = self
            .follow_distance
            .saturating_sub(self.cache_follow_distance());

        let length = voting_windows + extra_follow_distance_blocks;

        // Allow for more blocks to account for blocks being generated faster than expected.
        // The cache expiry should really be timestamp based, but that would require a more
        // extensive refactor.
        let cache_size = CACHE_FACTOR * length;

        self.block_cache_truncation = Some(cache_size as usize);
    }

    /// The distance at which the cache should follow the head.
    ///
    /// Defaults to 3/4 of `follow_distance` unless set manually.
    pub fn cache_follow_distance(&self) -> u64 {
        self.cache_follow_distance
            .unwrap_or(3 * self.follow_distance / 4)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: Eth1Endpoint::NoAuth(
                SensitiveUrl::parse(DEFAULT_ETH1_ENDPOINT)
                    .expect("The default Eth1 endpoint must always be a valid URL."),
            ),
            deposit_contract_address: "0x0000000000000000000000000000000000000000".into(),
            chain_id: DEFAULT_CHAIN_ID,
            deposit_contract_deploy_block: 1,
            lowest_cached_block_number: 1,
            follow_distance: 128,
            cache_follow_distance: None,
            node_far_behind_seconds: 128 * 14,
            block_cache_truncation: Some(4_096),
            auto_update_interval_millis: 60_000,
            blocks_per_log_query: 1_000,
            max_log_requests_per_update: Some(5_000),
            max_blocks_per_update: Some(8_192),
            purge_cache: false,
            execution_timeout_multiplier: 1,
        }
    }
}

pub fn endpoint_from_config(config: &Config, spec: &ChainSpec) -> Result<HttpJsonRpc, String> {
    match config.endpoint.clone() {
        Eth1Endpoint::Auth {
            endpoint,
            jwt_path,
            jwt_id,
            jwt_version,
        } => {
            let auth = Auth::new_with_path(jwt_path, jwt_id, jwt_version)
                .map_err(|e| format!("Failed to initialize jwt auth: {:?}", e))?;
            HttpJsonRpc::new_with_auth(
                endpoint,
                auth,
                Some(config.execution_timeout_multiplier),
                spec,
            )
            .map_err(|e| format!("Failed to create eth1 json rpc client: {:?}", e))
        }
        Eth1Endpoint::NoAuth(endpoint) => {
            HttpJsonRpc::new(endpoint, Some(config.execution_timeout_multiplier), spec)
                .map_err(|e| format!("Failed to create eth1 json rpc client: {:?}", e))
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
    pub fn new(config: Config, log: Logger, spec: ChainSpec) -> Result<Self, String> {
        Ok(Self {
            inner: Arc::new(Inner {
                block_cache: <_>::default(),
                deposit_cache: RwLock::new(DepositUpdater::new(
                    config.deposit_contract_deploy_block,
                )),
                endpoint: endpoint_from_config(&config, &spec)?,
                to_finalize: RwLock::new(None),
                remote_head_block: RwLock::new(None),
                config: RwLock::new(config),
                spec,
            }),
            log,
        })
    }

    pub fn client(&self) -> &HttpJsonRpc {
        &self.inner.endpoint
    }

    /// Creates a new service, initializing the deposit tree from a snapshot.
    pub fn from_deposit_snapshot(
        config: Config,
        log: Logger,
        spec: ChainSpec,
        deposit_snapshot: &DepositTreeSnapshot,
    ) -> Result<Self, Error> {
        let deposit_cache =
            DepositUpdater::from_snapshot(config.deposit_contract_deploy_block, deposit_snapshot)
                .map_err(Error::FailedToInitializeFromSnapshot)?;

        Ok(Self {
            inner: Arc::new(Inner {
                block_cache: <_>::default(),
                deposit_cache: RwLock::new(deposit_cache),
                endpoint: endpoint_from_config(&config, &spec)
                    .map_err(Error::FailedToInitializeFromSnapshot)?,
                to_finalize: RwLock::new(None),
                remote_head_block: RwLock::new(None),
                config: RwLock::new(config),
                spec,
            }),
            log,
        })
    }

    pub fn set_to_finalize(&self, eth1_data: Option<Eth1Data>) {
        *(self.inner.to_finalize.write()) = eth1_data;
    }

    /// Returns the follow distance that has been shortened to accommodate for differences in the
    /// spacing between blocks.
    ///
    /// ## Notes
    ///
    /// This is useful since the spec declares `SECONDS_PER_ETH1_BLOCK` to be `14`, whilst it is
    /// actually `15` on Goerli.
    pub fn cache_follow_distance(&self) -> u64 {
        self.config().cache_follow_distance()
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

    /// Returns the latest head block returned from an Eth1 node.
    ///
    /// ## Note
    ///
    /// This is the simply the head of the Eth1 chain, with no regard to follow distance or the
    /// voting period start.
    pub fn head_block(&self) -> Option<Eth1Block> {
        self.inner.remote_head_block.read().as_ref().cloned()
    }

    /// Returns the latest cached block.
    pub fn latest_cached_block(&self) -> Option<Eth1Block> {
        self.inner.block_cache.read().latest_block().cloned()
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
            .get_valid_signature_count(deposits.cache.latest_block_number())
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
        let client = self.client();
        let log = self.log.clone();
        let chain_id = self.config().chain_id.clone();
        let node_far_behind_seconds = self.inner.config.read().node_far_behind_seconds;

        match endpoint_state(client, &chain_id, &log).await {
            Ok(()) => crate::metrics::set_gauge(&metrics::ETH1_CONNECTED, 1),
            Err(e) => {
                crate::metrics::set_gauge(&metrics::ETH1_CONNECTED, 0);
                return Err(format!("Invalid endpoint state: {:?}", e));
            }
        }
        let (remote_head_block, new_block_numbers_deposit, new_block_numbers_block_cache) =
            get_remote_head_and_new_block_ranges(client, self, node_far_behind_seconds)
                .await
                .map_err(|e| format!("Failed to get remote head and new block ranges: {:?}", e))?;

        *self.inner.remote_head_block.write() = Some(remote_head_block);

        let update_deposit_cache = async {
            let outcome_result = self
                .update_deposit_cache(Some(new_block_numbers_deposit))
                .await;

            // Reset the `last_procesed block` to the last valid deposit's block number.
            // This will ensure that the next batch of blocks fetched is immediately after
            // the last cached valid deposit allowing us to recover from scenarios where
            // the deposit cache gets corrupted due to invalid responses from eth1 nodes.
            if let Err(Error::FailedToInsertDeposit(DepositCacheError::NonConsecutive {
                log_index: _,
                expected: _,
            })) = &outcome_result
            {
                let mut deposit_cache = self.inner.deposit_cache.write();
                debug!(
                    self.log,
                    "Resetting last processed block";
                    "old_block_number" => deposit_cache.last_processed_block,
                    "new_block_number" => deposit_cache.cache.latest_block_number(),
                );
                deposit_cache.last_processed_block =
                    Some(deposit_cache.cache.latest_block_number());
            }

            let outcome =
                outcome_result.map_err(|e| format!("Failed to update deposit cache: {:?}", e))?;

            trace!(
                self.log,
                "Updated deposit cache";
                "cached_deposits" => self.inner.deposit_cache.read().cache.len(),
                "logs_imported" => outcome.logs_imported,
                "last_processed_execution_block" => self.inner.deposit_cache.read().last_processed_block,
            );
            Ok::<_, String>(outcome)
        };

        let update_block_cache = async {
            let outcome = self
                .update_block_cache(Some(new_block_numbers_block_cache))
                .await
                .map_err(|e| format!("Failed to update deposit contract block cache: {:?}", e))?;

            trace!(
                self.log,
                "Updated deposit contract block cache";
                "cached_blocks" => self.inner.block_cache.read().len(),
                "blocks_imported" => outcome.blocks_imported,
                "head_block" => outcome.head_block_number,
            );
            Ok::<_, String>(outcome)
        };

        let (deposit_outcome, block_outcome) =
            futures::try_join!(update_deposit_cache, update_block_cache)?;

        Ok((deposit_outcome, block_outcome))
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
    pub fn auto_update(self, handle: task_executor::TaskExecutor) {
        let update_interval = Duration::from_millis(self.config().auto_update_interval_millis);

        let mut interval = interval_at(Instant::now(), update_interval);

        let update_future = async move {
            loop {
                interval.tick().await;
                self.do_update(update_interval).await.ok();
            }
        };

        handle.spawn(update_future, "eth1");
    }

    async fn do_update(&self, update_interval: Duration) -> Result<(), ()> {
        let update_result = self.update().await;
        match update_result {
            Err(e) => error!(
                self.log,
                "Error updating deposit contract cache";
                "retry_millis" => update_interval.as_millis(),
                "error" => e,
            ),
            Ok((deposit, block)) => debug!(
                self.log,
                "Updated deposit contract cache";
                "retry_millis" => update_interval.as_millis(),
                "blocks" => format!("{:?}", block),
                "deposits" => format!("{:?}", deposit),
            ),
        };
        let optional_eth1data = self.inner.to_finalize.write().take();
        if let Some(eth1data_to_finalize) = optional_eth1data {
            let already_finalized = self
                .inner
                .deposit_cache
                .read()
                .cache
                .finalized_deposit_count();
            let deposit_count_to_finalize = eth1data_to_finalize.deposit_count;
            if deposit_count_to_finalize > already_finalized {
                match self.finalize_deposits(eth1data_to_finalize) {
                    Err(e) => warn!(
                        self.log,
                        "Failed to finalize deposit cache";
                        "error" => ?e,
                        "info" => "this should resolve on its own"
                    ),
                    Ok(()) => info!(
                        self.log,
                        "Successfully finalized deposit tree";
                        "finalized deposit count" => deposit_count_to_finalize,
                    ),
                }
            } else {
                debug!(
                    self.log,
                    "Deposits tree already finalized";
                    "already_finalized" => already_finalized,
                    "deposit_count_to_finalize" => deposit_count_to_finalize,
                );
            }
        }
        Ok(())
    }

    /// Returns the range of new block numbers to be considered for the given head type.
    fn relevant_new_block_numbers(
        &self,
        remote_highest_block_number: u64,
        remote_highest_block_timestamp: Option<u64>,
        head_type: HeadType,
    ) -> Result<Option<RangeInclusive<u64>>, Error> {
        let follow_distance = self.cache_follow_distance();
        let latest_cached_block = self.latest_cached_block();
        let next_required_block = match head_type {
            HeadType::Deposit => self
                .deposits()
                .read()
                .last_processed_block
                .map(|n| n + 1)
                .unwrap_or_else(|| self.config().deposit_contract_deploy_block),
            HeadType::BlockCache => latest_cached_block
                .as_ref()
                .map(|block| block.number + 1)
                .unwrap_or_else(|| self.config().lowest_cached_block_number),
        };

        relevant_block_range(
            remote_highest_block_number,
            remote_highest_block_timestamp,
            next_required_block,
            follow_distance,
            latest_cached_block.as_ref(),
            &self.inner.spec,
        )
    }

    pub fn finalize_deposits(&self, eth1_data: Eth1Data) -> Result<(), Error> {
        let eth1_block = self
            .inner
            .block_cache
            .read()
            .block_by_hash(&eth1_data.block_hash)
            .cloned()
            .ok_or_else(|| {
                Error::FailedToFinalizeDeposit(format!(
                    "Finalized block not found in block cache: {:?}",
                    eth1_data.block_hash
                ))
            })?;
        self.inner
            .deposit_cache
            .write()
            .cache
            .finalize(eth1_block)
            .map_err(|e| Error::FailedToFinalizeDeposit(format!("{:?}", e)))
    }

    pub fn get_deposit_snapshot(&self) -> Option<DepositTreeSnapshot> {
        self.inner.deposit_cache.read().cache.get_deposit_snapshot()
    }

    /// Contacts the remote eth1 node and attempts to import deposit logs up to the configured
    /// follow-distance block.
    ///
    /// Will process no more than `BLOCKS_PER_LOG_QUERY * MAX_LOG_REQUESTS_PER_UPDATE` blocks in a
    /// single update.
    ///
    /// If `remote_highest_block_opt` is `Some`, use that value instead of querying `self.endpoint`
    /// for the head of the eth1 chain.
    ///
    /// ## Resolves with
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub async fn update_deposit_cache(
        &self,
        new_block_numbers: Option<Option<RangeInclusive<u64>>>,
    ) -> Result<DepositCacheUpdateOutcome, Error> {
        let client = self.client();
        let deposit_contract_address = self.config().deposit_contract_address.clone();

        let blocks_per_log_query = self.config().blocks_per_log_query;
        let max_log_requests_per_update = self
            .config()
            .max_log_requests_per_update
            .unwrap_or_else(usize::max_value);

        let range = {
            match new_block_numbers {
                Some(range) => range,
                None => {
                    relevant_new_block_numbers_from_endpoint(client, self, HeadType::Deposit)
                        .await?
                }
            }
        };

        let block_number_chunks = if let Some(range) = range {
            range
                .collect::<Vec<u64>>()
                .chunks(blocks_per_log_query)
                .take(max_log_requests_per_update)
                .map(|vec| {
                    let first = vec.first().cloned().unwrap_or(0);
                    let last = vec.last().map(|n| n + 1).unwrap_or(0);
                    first..last
                })
                .collect::<Vec<Range<u64>>>()
        } else {
            Vec::new()
        };

        let mut logs_imported: usize = 0;
        let deposit_contract_address_ref: &str = &deposit_contract_address;
        for block_range in block_number_chunks.into_iter() {
            if block_range.is_empty() {
                debug!(
                    self.log,
                    "No new blocks to scan for logs";
                );
                continue;
            }

            /*
             * Step 1. Download logs.
             */
            let block_range_ref = &block_range;
            let logs = client
                .get_deposit_logs_in_range(
                    deposit_contract_address_ref,
                    block_range_ref.clone(),
                    Duration::from_millis(GET_DEPOSIT_LOG_TIMEOUT_MILLIS),
                )
                .await
                .map_err(Error::GetDepositLogsFailed)?;

            /*
             * Step 2. Import logs to cache.
             */
            let mut cache = self.deposits().write();
            logs.iter()
                .map(|raw_log| {
                    raw_log.to_deposit_log(self.inner.spec()).map_err(|error| {
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
                // Returns if a deposit is unable to be added to the cache.
                //
                // If this error occurs, the cache will no longer be guaranteed to hold either
                // none or all of the logs for each block (i.e., they may exist _some_ logs for
                // a block, but not _all_ logs for that block). This scenario can cause the
                // node to choose an invalid genesis state or propose an invalid block.
                .try_for_each(|deposit_log| {
                    if let DepositCacheInsertOutcome::Inserted = cache
                        .cache
                        .insert_log(deposit_log)
                        .map_err(Error::FailedToInsertDeposit)?
                    {
                        logs_imported += 1;
                    }

                    Ok::<_, Error>(())
                })?;

            debug!(
                self.log,
                "Imported deposit logs chunk";
                "logs" => logs.len(),
            );

            cache.last_processed_block = Some(block_range.end.saturating_sub(1));

            metrics::set_gauge(&metrics::DEPOSIT_CACHE_LEN, cache.cache.len() as i64);
            metrics::set_gauge(
                &metrics::HIGHEST_PROCESSED_DEPOSIT_BLOCK,
                cache.last_processed_block.unwrap_or(0) as i64,
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
    /// If `remote_highest_block_opt` is `Some`, use that value instead of querying `self.endpoint`
    /// for the head of the eth1 chain.
    ///
    /// ## Resolves with
    ///
    /// - Ok(_) if the update was successful (the cache may or may not have been modified).
    /// - Err(_) if there is an error.
    ///
    /// Emits logs for debugging and errors.
    pub async fn update_block_cache(
        &self,
        new_block_numbers: Option<Option<RangeInclusive<u64>>>,
    ) -> Result<BlockCacheUpdateOutcome, Error> {
        let client = self.client();
        let block_cache_truncation = self.config().block_cache_truncation;
        let max_blocks_per_update = self
            .config()
            .max_blocks_per_update
            .unwrap_or_else(usize::max_value);

        let range = {
            match new_block_numbers {
                Some(range) => range,
                None => {
                    relevant_new_block_numbers_from_endpoint(client, self, HeadType::BlockCache)
                        .await?
                }
            }
        };

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

        // This value is used to prevent the block cache from importing a block that is not yet in
        // the deposit cache.
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

        debug!(
            self.log,
            "Downloading execution blocks";
            "first" => ?required_block_numbers.first(),
            "last" => ?required_block_numbers.last(),
        );

        // Produce a stream from the list of required block numbers and return a future that
        // consumes the it.

        let mut blocks_imported = 0;
        for block_number in required_block_numbers {
            let eth1_block =
                download_eth1_block(client, self.inner.clone(), Some(block_number)).await?;

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
                    .unwrap_or(0) as i64,
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
                "Imported execution block(s)";
                "latest_block_age" => latest_block_mins,
                "latest_block" => block_cache.highest_block_number(),
                "total_cached_blocks" => block_cache.len(),
                "new" => %blocks_imported
            );
        } else {
            debug!(
                self.log,
                "No new execution blocks imported";
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

/// Returns the range of blocks starting from `next_required_block` that are at least
/// `follow_distance` many blocks before `remote_highest_block`.
/// Returns an error if `next_required_block > remote_highest_block + 1` which means the remote went
/// backwards.
fn relevant_block_range(
    remote_highest_block_number: u64,
    remote_highest_block_timestamp: Option<u64>,
    next_required_block: u64,
    cache_follow_distance: u64,
    latest_cached_block: Option<&Eth1Block>,
    spec: &ChainSpec,
) -> Result<Option<RangeInclusive<u64>>, Error> {
    // If the latest cached block is lagging the head block by more than `cache_follow_distance`
    // times the expected block time then the eth1 block time is likely quite different from what we
    // assumed.
    //
    // In order to catch up, load batches of `CATCHUP_BATCH_SIZE` until the situation rights itself.
    // Note that we need to check this condition before the regular follow distance condition
    // or we will keep downloading small numbers of blocks.
    if let (Some(remote_highest_block_timestamp), Some(latest_cached_block)) =
        (remote_highest_block_timestamp, latest_cached_block)
    {
        let lagging = latest_cached_block.timestamp
            + cache_follow_distance * spec.seconds_per_eth1_block
            < remote_highest_block_timestamp;
        let end_block = std::cmp::max(
            std::cmp::min(
                remote_highest_block_number.saturating_sub(CATCHUP_MIN_FOLLOW_DISTANCE),
                next_required_block + CATCHUP_BATCH_SIZE,
            ),
            remote_highest_block_number.saturating_sub(cache_follow_distance),
        );
        if lagging && next_required_block <= end_block {
            return Ok(Some(next_required_block..=end_block));
        }
    }

    let remote_follow_block = remote_highest_block_number.saturating_sub(cache_follow_distance);
    if next_required_block <= remote_follow_block {
        Ok(Some(next_required_block..=remote_follow_block))
    } else if next_required_block > remote_highest_block_number + 1 {
        // If this is the case, the node must have gone "backwards" in terms of it's sync
        // (i.e., it's head block is lower than it was before).
        //
        // We assume that the `cache_follow_distance` should be sufficient to ensure this never
        // happens, otherwise it is an error.
        Err(Error::RemoteNotSynced {
            next_required_block,
            remote_highest_block: remote_highest_block_number,
            cache_follow_distance,
        })
    } else {
        // Return an empty range.
        Ok(None)
    }
}

/// Downloads the `(block, deposit_root, deposit_count)` tuple from an eth1 node for the given
/// `block_number`.
///
/// Set `block_number_opt = None` to get the "latest" eth1 block (i.e., the head).
///
/// Performs three async calls to an Eth1 HTTP JSON RPC endpoint.
async fn download_eth1_block(
    endpoint: &HttpJsonRpc,
    cache: Arc<Inner>,
    block_number_opt: Option<u64>,
) -> Result<Eth1Block, Error> {
    let deposit_root = block_number_opt.and_then(|block_number| {
        cache
            .deposit_cache
            .read()
            .cache
            .get_deposit_root_from_cache(block_number)
    });

    let deposit_count = block_number_opt.and_then(|block_number| {
        cache
            .deposit_cache
            .read()
            .cache
            .get_deposit_count_from_cache(block_number)
    });

    // Performs a `get_blockByNumber` call to an eth1 node.
    let http_block = endpoint
        .get_block(
            block_number_opt
                .map(BlockQuery::Number)
                .unwrap_or_else(|| BlockQuery::Latest),
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
    use types::MainnetEthSpec;

    #[test]
    // Ensures the default config does not panic.
    fn default_config() {
        Config::default();
    }

    #[test]
    fn serde_serialize() {
        let serialized =
            serde_yaml::to_string(&Config::default()).expect("Should serde encode default config");
        serde_yaml::from_str::<Config>(&serialized).expect("Should serde decode default config");
    }

    #[test]
    fn block_cache_size() {
        let mut config = Config::default();

        let spec = MainnetEthSpec::default_spec();

        config.set_block_cache_truncation::<MainnetEthSpec>(&spec);

        let len = config.block_cache_truncation.unwrap();

        let seconds_per_voting_period =
            <MainnetEthSpec as EthSpec>::SlotsPerEth1VotingPeriod::to_u64() * spec.seconds_per_slot;
        let eth1_blocks_per_voting_period = seconds_per_voting_period / spec.seconds_per_eth1_block;
        let cache_follow_distance_blocks = config.follow_distance - config.cache_follow_distance();

        let minimum_len = eth1_blocks_per_voting_period * 2 + cache_follow_distance_blocks;

        assert!(len > minimum_len as usize);
    }
}
