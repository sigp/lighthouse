use crate::metrics;
use crate::{
    block_cache::{BlockCache, Error as BlockCacheError, Eth1Block},
    deposit_cache::{DepositCacheInsertOutcome, Error as DepositCacheError},
    http::{
        get_block, get_block_number, get_chain_id, get_deposit_logs_in_range, get_network_id,
        BlockQuery, Eth1Id,
    },
    inner::{DepositUpdater, Inner},
};
use fallback::{Fallback, FallbackError};
use futures::future::TryFutureExt;
use parking_lot::{RwLock, RwLockReadGuard};
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, warn, Logger};
use std::fmt::Debug;
use std::future::Future;
use std::ops::{Range, RangeInclusive};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock as TRwLock;
use tokio::time::{interval_at, Duration, Instant};
use types::{ChainSpec, EthSpec, Unsigned};

/// Indicates the default eth1 network id we use for the deposit contract.
pub const DEFAULT_NETWORK_ID: Eth1Id = Eth1Id::Goerli;
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

const WARNING_MSG: &str = "BLOCK PROPOSALS WILL FAIL WITHOUT VALID, SYNCED ETH1 CONNECTION";

/// A factor used to reduce the eth1 follow distance to account for discrepancies in the block time.
const ETH1_BLOCK_TIME_TOLERANCE_FACTOR: u64 = 4;

#[derive(Debug, PartialEq, Clone)]
pub enum EndpointError {
    RequestFailed(String),
    WrongNetworkId,
    WrongChainId,
    FarBehind,
}

type EndpointState = Result<(), EndpointError>;

pub struct EndpointWithState {
    endpoint: SensitiveUrl,
    state: TRwLock<Option<EndpointState>>,
}

impl EndpointWithState {
    pub fn new(endpoint: SensitiveUrl) -> Self {
        Self {
            endpoint,
            state: TRwLock::new(None),
        }
    }
}

async fn reset_endpoint_state(endpoint: &EndpointWithState) {
    *endpoint.state.write().await = None;
}

async fn get_state(endpoint: &EndpointWithState) -> Option<EndpointState> {
    endpoint.state.read().await.clone()
}

/// A cache structure to lazily check usability of endpoints. An endpoint is usable if it is
/// reachable and has the correct network id and chain id. Emits a `WARN` log if a checked endpoint
/// is not usable.
pub struct EndpointsCache {
    pub fallback: Fallback<EndpointWithState>,
    pub config_network_id: Eth1Id,
    pub config_chain_id: Eth1Id,
    pub log: Logger,
}

impl EndpointsCache {
    /// Checks the usability of an endpoint. Results get cached and therefore only the first call
    /// for each endpoint does the real check.
    async fn state(&self, endpoint: &EndpointWithState) -> EndpointState {
        if let Some(result) = endpoint.state.read().await.clone() {
            return result;
        }
        let mut value = endpoint.state.write().await;
        if let Some(result) = value.clone() {
            return result;
        }
        crate::metrics::inc_counter_vec(
            &crate::metrics::ENDPOINT_REQUESTS,
            &[&endpoint.endpoint.to_string()],
        );
        let state = endpoint_state(
            &endpoint.endpoint,
            &self.config_network_id,
            &self.config_chain_id,
            &self.log,
        )
        .await;
        *value = Some(state.clone());
        if state.is_err() {
            crate::metrics::inc_counter_vec(
                &crate::metrics::ENDPOINT_ERRORS,
                &[&endpoint.endpoint.to_string()],
            );
            crate::metrics::set_gauge(&metrics::ETH1_CONNECTED, 0);
        } else {
            crate::metrics::set_gauge(&metrics::ETH1_CONNECTED, 1);
        }
        state
    }

    pub async fn first_success<'a, F, O, R>(
        &'a self,
        func: F,
    ) -> Result<O, FallbackError<SingleEndpointError>>
    where
        F: Fn(&'a SensitiveUrl) -> R,
        R: Future<Output = Result<O, SingleEndpointError>>,
    {
        let func = &func;
        self.fallback
            .first_success(|endpoint| async move {
                match self.state(endpoint).await {
                    Ok(()) => {
                        let endpoint_str = &endpoint.endpoint.to_string();
                        crate::metrics::inc_counter_vec(
                            &crate::metrics::ENDPOINT_REQUESTS,
                            &[endpoint_str],
                        );
                        match func(&endpoint.endpoint).await {
                            Ok(t) => Ok(t),
                            Err(t) => {
                                crate::metrics::inc_counter_vec(
                                    &crate::metrics::ENDPOINT_ERRORS,
                                    &[endpoint_str],
                                );
                                if let SingleEndpointError::EndpointError(e) = &t {
                                    *endpoint.state.write().await = Some(Err(e.clone()));
                                } else {
                                    // A non-`EndpointError` error occurred, so reset the state.
                                    reset_endpoint_state(endpoint).await;
                                }
                                Err(t)
                            }
                        }
                    }
                    Err(e) => Err(SingleEndpointError::EndpointError(e)),
                }
            })
            .await
    }

    pub async fn reset_errorred_endpoints(&self) {
        for endpoint in &self.fallback.servers {
            if let Some(state) = get_state(endpoint).await {
                if state.is_err() {
                    reset_endpoint_state(endpoint).await;
                }
            }
        }
    }
}

/// Returns `Ok` if the endpoint is usable, i.e. is reachable and has a correct network id and
/// chain id. Otherwise it returns `Err`.
async fn endpoint_state(
    endpoint: &SensitiveUrl,
    config_network_id: &Eth1Id,
    config_chain_id: &Eth1Id,
    log: &Logger,
) -> EndpointState {
    let error_connecting = |e| {
        warn!(
            log,
            "Error connecting to eth1 node endpoint";
            "endpoint" => %endpoint,
            "action" => "trying fallbacks"
        );
        EndpointError::RequestFailed(e)
    };
    let network_id = get_network_id(endpoint, Duration::from_millis(STANDARD_TIMEOUT_MILLIS))
        .await
        .map_err(error_connecting)?;
    if &network_id != config_network_id {
        warn!(
            log,
            "Invalid eth1 network id on endpoint. Please switch to correct network id";
            "endpoint" => %endpoint,
            "action" => "trying fallbacks",
            "expected" => format!("{:?}",config_network_id),
            "received" => format!("{:?}",network_id),
        );
        return Err(EndpointError::WrongNetworkId);
    }
    let chain_id = get_chain_id(endpoint, Duration::from_millis(STANDARD_TIMEOUT_MILLIS))
        .await
        .map_err(error_connecting)?;
    // Eth1 nodes return chain_id = 0 if the node is not synced
    // Handle the special case
    if chain_id == Eth1Id::Custom(0) {
        warn!(
            log,
            "Remote eth1 node is not synced";
            "endpoint" => %endpoint,
            "action" => "trying fallbacks"
        );
        return Err(EndpointError::FarBehind);
    }
    if &chain_id != config_chain_id {
        warn!(
            log,
            "Invalid eth1 chain id. Please switch to correct chain id on endpoint";
            "endpoint" => %endpoint,
            "action" => "trying fallbacks",
            "expected" => format!("{:?}",config_chain_id),
            "received" => format!("{:?}", chain_id),
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
    endpoint: &SensitiveUrl,
    service: &Service,
    node_far_behind_seconds: u64,
) -> Result<
    (
        Eth1Block,
        Option<RangeInclusive<u64>>,
        Option<RangeInclusive<u64>>,
    ),
    SingleEndpointError,
> {
    let remote_head_block = download_eth1_block(endpoint, service.inner.clone(), None).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    if remote_head_block.timestamp + node_far_behind_seconds < now {
        warn!(
            service.log,
            "Eth1 endpoint is not synced";
            "endpoint" => %endpoint,
            "last_seen_block_unix_timestamp" => remote_head_block.timestamp,
            "action" => "trying fallback"
        );
        return Err(SingleEndpointError::EndpointError(EndpointError::FarBehind));
    }

    let handle_remote_not_synced = |e| {
        if let SingleEndpointError::RemoteNotSynced { .. } = e {
            warn!(
                service.log,
                "Eth1 endpoint is not synced";
                "endpoint" => %endpoint,
                "action" => "trying fallbacks"
            );
        }
        e
    };
    let new_deposit_block_numbers = service
        .relevant_new_block_numbers(remote_head_block.number, HeadType::Deposit)
        .map_err(handle_remote_not_synced)?;
    let new_block_cache_numbers = service
        .relevant_new_block_numbers(remote_head_block.number, HeadType::BlockCache)
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
    endpoint: &SensitiveUrl,
    service: &Service,
    head_type: HeadType,
) -> Result<Option<RangeInclusive<u64>>, SingleEndpointError> {
    let remote_highest_block =
        get_block_number(endpoint, Duration::from_millis(BLOCK_NUMBER_TIMEOUT_MILLIS))
            .map_err(SingleEndpointError::GetBlockNumberFailed)
            .await?;
    service.relevant_new_block_numbers(remote_highest_block, head_type)
}

#[derive(Debug, PartialEq)]
pub enum SingleEndpointError {
    /// Endpoint is currently not functional.
    EndpointError(EndpointError),
    /// The remote node is less synced that we expect, it is not useful until has done more
    /// syncing.
    RemoteNotSynced {
        next_required_block: u64,
        remote_highest_block: u64,
        reduced_follow_distance: u64,
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
    /// All possible endpoints returned a `SingleEndpointError`.
    FallbackError(FallbackError<SingleEndpointError>),
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
    pub endpoints: Vec<SensitiveUrl>,
    /// The address the `BlockCache` and `DepositCache` should assume is the canonical deposit contract.
    pub deposit_contract_address: String,
    /// The eth1 network id where the deposit contract is deployed (Goerli/Mainnet).
    pub network_id: Eth1Id,
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
}

impl Config {
    /// Sets the block cache to a length that is suitable for the given `EthSpec` and `ChainSpec`.
    pub fn set_block_cache_truncation<E: EthSpec>(&mut self, spec: &ChainSpec) {
        // Compute the number of eth1 blocks in an eth1 voting period.
        let seconds_per_voting_period =
            E::SlotsPerEth1VotingPeriod::to_u64() * spec.seconds_per_slot;
        let eth1_blocks_per_voting_period = seconds_per_voting_period / spec.seconds_per_eth1_block;

        // Compute the number of extra blocks we store prior to the voting period start blocks.
        let follow_distance_tolerance_blocks =
            spec.eth1_follow_distance / ETH1_BLOCK_TIME_TOLERANCE_FACTOR;

        // Ensure we can store two full windows of voting blocks.
        let voting_windows = eth1_blocks_per_voting_period * 2;

        // Extend the cache to account for varying eth1 block times and the follow distance
        // tolerance blocks.
        let length = voting_windows
            + (voting_windows / ETH1_BLOCK_TIME_TOLERANCE_FACTOR)
            + follow_distance_tolerance_blocks;

        self.block_cache_truncation = Some(length as usize);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoints: vec![SensitiveUrl::parse(DEFAULT_ETH1_ENDPOINT)
                .expect("The default Eth1 endpoint must always be a valid URL.")],
            deposit_contract_address: "0x0000000000000000000000000000000000000000".into(),
            network_id: DEFAULT_NETWORK_ID,
            chain_id: DEFAULT_CHAIN_ID,
            deposit_contract_deploy_block: 1,
            lowest_cached_block_number: 1,
            follow_distance: 128,
            node_far_behind_seconds: 128 * 14,
            block_cache_truncation: Some(4_096),
            auto_update_interval_millis: 60_000,
            blocks_per_log_query: 1_000,
            max_log_requests_per_update: Some(5_000),
            max_blocks_per_update: Some(8_192),
            purge_cache: false,
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
                endpoints_cache: RwLock::new(None),
                remote_head_block: RwLock::new(None),
                config: RwLock::new(config),
                spec,
            }),
            log,
        }
    }

    /// Returns the follow distance that has been shortened to accommodate for differences in the
    /// spacing between blocks.
    ///
    /// ## Notes
    ///
    /// This is useful since the spec declares `SECONDS_PER_ETH1_BLOCK` to be `14`, whilst it is
    /// actually `15` on Goerli.
    pub fn reduced_follow_distance(&self) -> u64 {
        let full = self.config().follow_distance;
        full.saturating_sub(full / ETH1_BLOCK_TIME_TOLERANCE_FACTOR)
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

    /// Builds a new `EndpointsCache` with empty states.
    pub fn init_endpoints(&self) -> Arc<EndpointsCache> {
        let endpoints = self.config().endpoints.clone();
        let config_network_id = self.config().network_id.clone();
        let config_chain_id = self.config().chain_id.clone();
        let new_cache = Arc::new(EndpointsCache {
            fallback: Fallback::new(endpoints.into_iter().map(EndpointWithState::new).collect()),
            config_network_id,
            config_chain_id,
            log: self.log.clone(),
        });

        let mut endpoints_cache = self.inner.endpoints_cache.write();
        *endpoints_cache = Some(new_cache.clone());
        new_cache
    }

    /// Returns the cached `EndpointsCache` if it exists or builds a new one.
    pub fn get_endpoints(&self) -> Arc<EndpointsCache> {
        let endpoints_cache = self.inner.endpoints_cache.read();
        if let Some(cache) = endpoints_cache.clone() {
            cache
        } else {
            drop(endpoints_cache);
            self.init_endpoints()
        }
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
        let endpoints = self.get_endpoints();

        // Reset the state of any endpoints which have errored so their state can be redetermined.
        endpoints.reset_errorred_endpoints().await;

        let node_far_behind_seconds = self.inner.config.read().node_far_behind_seconds;

        let process_single_err = |e: &FallbackError<SingleEndpointError>| {
            match e {
                FallbackError::AllErrored(errors) => {
                    if errors
                        .iter()
                        .all(|error| matches!(error, SingleEndpointError::EndpointError(_)))
                    {
                        crit!(
                            self.log,
                            "Couldn't connect to any eth1 node. Please ensure that you have an \
                             eth1 http server running locally on http://localhost:8545 or specify \
                             one or more (remote) endpoints using \
                             `--eth1-endpoints <COMMA-SEPARATED-SERVER-ADDRESSES>`. \
                             Also ensure that `eth` and `net` apis are enabled on the eth1 http \
                             server";
                             "warning" => WARNING_MSG
                        );
                    }
                }
            }
            endpoints.fallback.map_format_error(|s| &s.endpoint, &e)
        };

        let process_err = |e: Error| match &e {
            Error::FallbackError(f) => process_single_err(f),
            e => format!("{:?}", e),
        };

        let (remote_head_block, new_block_numbers_deposit, new_block_numbers_block_cache) =
            endpoints
                .first_success(|e| async move {
                    get_remote_head_and_new_block_ranges(e, &self, node_far_behind_seconds).await
                })
                .await
                .map_err(|e| {
                    format!(
                        "Failed to update Eth1 service: {:?}",
                        process_single_err(&e)
                    )
                })?;

        *self.inner.remote_head_block.write() = Some(remote_head_block);

        let update_deposit_cache = async {
            let outcome = self
                .update_deposit_cache(Some(new_block_numbers_deposit), &endpoints)
                .await
                .map_err(|e| {
                    format!("Failed to update eth1 deposit cache: {:?}", process_err(e))
                })?;

            trace!(
                self.log,
                "Updated eth1 deposit cache";
                "cached_deposits" => self.inner.deposit_cache.read().cache.len(),
                "logs_imported" => outcome.logs_imported,
                "last_processed_eth1_block" => self.inner.deposit_cache.read().last_processed_block,
            );
            Ok::<_, String>(outcome)
        };

        let update_block_cache = async {
            let outcome = self
                .update_block_cache(Some(new_block_numbers_block_cache), &endpoints)
                .await
                .map_err(|e| format!("Failed to update eth1 block cache: {:?}", process_err(e)))?;

            trace!(
                self.log,
                "Updated eth1 block cache";
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

        let num_fallbacks = self.config().endpoints.len() - 1;
        let update_future = async move {
            loop {
                interval.tick().await;
                self.do_update(update_interval).await.ok();
            }
        };

        // Set the number of configured eth1 servers
        metrics::set_gauge(&metrics::ETH1_FALLBACK_CONFIGURED, num_fallbacks as i64);
        // Since we lazily update eth1 fallbacks, it's not possible to know connection status of fallback.
        // Hence, we set it to 1 if we have atleast one configured fallback.
        if num_fallbacks > 0 {
            metrics::set_gauge(&metrics::ETH1_FALLBACK_CONNECTED, 1);
        } else {
            metrics::set_gauge(&metrics::ETH1_FALLBACK_CONNECTED, 0);
        }
        handle.spawn(update_future, "eth1");
    }

    async fn do_update(&self, update_interval: Duration) -> Result<(), ()> {
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

    /// Returns the range of new block numbers to be considered for the given head type.
    fn relevant_new_block_numbers(
        &self,
        remote_highest_block: u64,
        head_type: HeadType,
    ) -> Result<Option<RangeInclusive<u64>>, SingleEndpointError> {
        let follow_distance = self.reduced_follow_distance();
        let next_required_block = match head_type {
            HeadType::Deposit => self
                .deposits()
                .read()
                .last_processed_block
                .map(|n| n + 1)
                .unwrap_or_else(|| self.config().deposit_contract_deploy_block),
            HeadType::BlockCache => self
                .inner
                .block_cache
                .read()
                .highest_block_number()
                .map(|n| n + 1)
                .unwrap_or_else(|| self.config().lowest_cached_block_number),
        };

        relevant_block_range(remote_highest_block, next_required_block, follow_distance)
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
        endpoints: &EndpointsCache,
    ) -> Result<DepositCacheUpdateOutcome, Error> {
        let deposit_contract_address = self.config().deposit_contract_address.clone();

        let blocks_per_log_query = self.config().blocks_per_log_query;
        let max_log_requests_per_update = self
            .config()
            .max_log_requests_per_update
            .unwrap_or_else(usize::max_value);

        let range = {
            match new_block_numbers {
                Some(range) => range,
                None => endpoints
                    .first_success(|e| async move {
                        relevant_new_block_numbers_from_endpoint(e, &self, HeadType::Deposit).await
                    })
                    .await
                    .map_err(Error::FallbackError)?,
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
            let logs = endpoints
                .first_success(|e| async move {
                    get_deposit_logs_in_range(
                        e,
                        &deposit_contract_address_ref,
                        block_range_ref.clone(),
                        Duration::from_millis(GET_DEPOSIT_LOG_TIMEOUT_MILLIS),
                    )
                    .await
                    .map_err(SingleEndpointError::GetDepositLogsFailed)
                })
                .await
                .map_err(Error::FallbackError)?;

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

                    Ok(())
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
        endpoints: &EndpointsCache,
    ) -> Result<BlockCacheUpdateOutcome, Error> {
        let block_cache_truncation = self.config().block_cache_truncation;
        let max_blocks_per_update = self
            .config()
            .max_blocks_per_update
            .unwrap_or_else(usize::max_value);

        let range = {
            match new_block_numbers {
                Some(range) => range,
                None => endpoints
                    .first_success(|e| async move {
                        relevant_new_block_numbers_from_endpoint(e, &self, HeadType::BlockCache)
                            .await
                    })
                    .await
                    .map_err(Error::FallbackError)?,
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
            "Downloading eth1 blocks";
            "first" => ?required_block_numbers.first(),
            "last" => ?required_block_numbers.last(),
        );

        // Produce a stream from the list of required block numbers and return a future that
        // consumes the it.

        let mut blocks_imported = 0;
        for block_number in required_block_numbers {
            let eth1_block = endpoints
                .first_success(|e| async move {
                    download_eth1_block(e, self.inner.clone(), Some(block_number)).await
                })
                .await
                .map_err(Error::FallbackError)?;

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

/// Returns the range of blocks starting from `next_required_block` that are at least
/// `follow_distance` many blocks before `remote_highest_block`.
/// Returns an error if `next_required_block > remote_highest_block + 1` which means the remote went
/// backwards.
fn relevant_block_range(
    remote_highest_block: u64,
    next_required_block: u64,
    reduced_follow_distance: u64,
) -> Result<Option<RangeInclusive<u64>>, SingleEndpointError> {
    let remote_follow_block = remote_highest_block.saturating_sub(reduced_follow_distance);

    if next_required_block <= remote_follow_block {
        Ok(Some(next_required_block..=remote_follow_block))
    } else if next_required_block > remote_highest_block + 1 {
        // If this is the case, the node must have gone "backwards" in terms of it's sync
        // (i.e., it's head block is lower than it was before).
        //
        // We assume that the `reduced_follow_distance` should be sufficient to ensure this never
        // happens, otherwise it is an error.
        Err(SingleEndpointError::RemoteNotSynced {
            next_required_block,
            remote_highest_block,
            reduced_follow_distance,
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
    endpoint: &SensitiveUrl,
    cache: Arc<Inner>,
    block_number_opt: Option<u64>,
) -> Result<Eth1Block, SingleEndpointError> {
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
    let http_block = get_block(
        endpoint,
        block_number_opt
            .map(BlockQuery::Number)
            .unwrap_or_else(|| BlockQuery::Latest),
        Duration::from_millis(GET_BLOCK_TIMEOUT_MILLIS),
    )
    .map_err(SingleEndpointError::BlockDownloadFailed)
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
            toml::to_string(&Config::default()).expect("Should serde encode default config");
        toml::from_str::<Config>(&serialized).expect("Should serde decode default config");
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
        let reduce_follow_distance_blocks =
            config.follow_distance / ETH1_BLOCK_TIME_TOLERANCE_FACTOR;

        let minimum_len = eth1_blocks_per_voting_period * 2 + reduce_follow_distance_blocks;

        assert!(len > minimum_len as usize);
    }
}
