//! This crate provides an abstraction over one or more *execution engines*. An execution engine
//! was formerly known as an "eth1 node", like Geth, Nethermind, Erigon, etc.
//!
//! This crate only provides useful functionality for "The Merge", it does not provide any of the
//! deposit-contract functionality that the `beacon_node/eth1` crate already provides.

use auth::{strip_prefix, Auth, JwtKey};
use builder_client::BuilderHttpClient;
use engine_api::Error as ApiError;
pub use engine_api::*;
pub use engine_api::{http, http::deposit_methods, http::HttpJsonRpc};
pub use engines::ForkChoiceState;
use engines::{Engine, EngineError, Engines, Logging};
use lru::LruCache;
use payload_status::process_payload_status;
pub use payload_status::PayloadStatus;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use task_executor::TaskExecutor;
use tokio::{
    sync::{Mutex, MutexGuard, RwLock},
    time::{sleep, sleep_until, Instant},
};
use types::{
    BlindedPayload, BlockType, ChainSpec, Epoch, ExecPayload, ExecutionBlockHash,
    ProposerPreparationData, PublicKeyBytes, SignedBeaconBlock, Slot,
};

mod engine_api;
mod engines;
mod metrics;
mod payload_status;
pub mod test_utils;

/// Indicates the default jwt authenticated execution endpoint.
pub const DEFAULT_EXECUTION_ENDPOINT: &str = "http://localhost:8551/";

/// Name for the default file used for the jwt secret.
pub const DEFAULT_JWT_FILE: &str = "jwt.hex";

/// Each time the `ExecutionLayer` retrieves a block from an execution node, it stores that block
/// in an LRU cache to avoid redundant lookups. This is the size of that cache.
const EXECUTION_BLOCKS_LRU_CACHE_SIZE: usize = 128;

/// A fee recipient address for use during block production. Only used as a very last resort if
/// there is no address provided by the user.
///
/// ## Note
///
/// This is *not* the zero-address, since Geth has been known to return errors for a coinbase of
/// 0x00..00.
const DEFAULT_SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum Error {
    NoEngines,
    NoPayloadBuilder,
    ApiError(ApiError),
    Builder(builder_client::Error),
    EngineError(Box<EngineError>),
    NotSynced,
    ShuttingDown,
    FeeRecipientUnspecified,
    MissingLatestValidHash,
    InvalidJWTSecret(String),
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

#[derive(Clone, PartialEq)]
pub struct ProposerPreparationDataEntry {
    update_epoch: Epoch,
    preparation_data: ProposerPreparationData,
}

#[derive(Hash, PartialEq, Eq)]
pub struct ProposerKey {
    slot: Slot,
    head_block_root: Hash256,
}

#[derive(PartialEq, Clone)]
pub struct Proposer {
    validator_index: u64,
    payload_attributes: PayloadAttributes,
}

struct Inner<E: EthSpec> {
    engines: Engines,
    builder: Option<BuilderHttpClient>,
    execution_engine_forkchoice_lock: Mutex<()>,
    suggested_fee_recipient: Option<Address>,
    proposer_preparation_data: Mutex<HashMap<u64, ProposerPreparationDataEntry>>,
    execution_blocks: Mutex<LruCache<ExecutionBlockHash, ExecutionBlock>>,
    proposers: RwLock<HashMap<ProposerKey, Proposer>>,
    executor: TaskExecutor,
    phantom: std::marker::PhantomData<E>,
    log: Logger,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint urls for EL nodes that are running the engine api.
    pub execution_endpoints: Vec<SensitiveUrl>,
    /// Endpoint urls for services providing the builder api.
    pub builder_url: Option<SensitiveUrl>,
    /// JWT secrets for the above endpoints running the engine api.
    pub secret_files: Vec<PathBuf>,
    /// The default fee recipient to use on the beacon node if none if provided from
    /// the validator client during block preparation.
    pub suggested_fee_recipient: Option<Address>,
    /// An optional id for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_id: Option<String>,
    /// An optional client version for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_version: Option<String>,
    /// Default directory for the jwt secret if not provided through cli.
    pub default_datadir: PathBuf,
}

/// Provides access to one or more execution engines and provides a neat interface for consumption
/// by the `BeaconChain`.
///
/// When there is more than one execution node specified, the others will be used in a "fallback"
/// fashion. Some requests may be broadcast to all nodes and others might only be sent to the first
/// node that returns a valid response. Ultimately, the purpose of fallback nodes is to provide
/// redundancy in the case where one node is offline.
///
/// The fallback nodes have an ordering. The first supplied will be the first contacted, and so on.
#[derive(Clone)]
pub struct ExecutionLayer<T: EthSpec> {
    inner: Arc<Inner<T>>,
}

impl<T: EthSpec> ExecutionLayer<T> {
    /// Instantiate `Self` with Execution engines specified using `Config`, all using the JSON-RPC via HTTP.
    pub fn from_config(config: Config, executor: TaskExecutor, log: Logger) -> Result<Self, Error> {
        let Config {
            execution_endpoints: urls,
            builder_url,
            secret_files,
            suggested_fee_recipient,
            jwt_id,
            jwt_version,
            default_datadir,
        } = config;

        if urls.len() > 1 {
            warn!(log, "Only the first execution engine url will be used");
        }
        let execution_url = urls.into_iter().next().ok_or(Error::NoEngines)?;

        // Use the default jwt secret path if not provided via cli.
        let secret_file = secret_files
            .into_iter()
            .next()
            .unwrap_or_else(|| default_datadir.join(DEFAULT_JWT_FILE));

        let jwt_key = if secret_file.exists() {
            // Read secret from file if it already exists
            std::fs::read_to_string(&secret_file)
                .map_err(|e| format!("Failed to read JWT secret file. Error: {:?}", e))
                .and_then(|ref s| {
                    let secret = JwtKey::from_slice(
                        &hex::decode(strip_prefix(s.trim_end()))
                            .map_err(|e| format!("Invalid hex string: {:?}", e))?,
                    )?;
                    Ok(secret)
                })
                .map_err(Error::InvalidJWTSecret)
        } else {
            // Create a new file and write a randomly generated secret to it if file does not exist
            std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(&secret_file)
                .map_err(|e| format!("Failed to open JWT secret file. Error: {:?}", e))
                .and_then(|mut f| {
                    let secret = auth::JwtKey::random();
                    f.write_all(secret.hex_string().as_bytes())
                        .map_err(|e| format!("Failed to write to JWT secret file: {:?}", e))?;
                    Ok(secret)
                })
                .map_err(Error::InvalidJWTSecret)
        }?;

        let engine: Engine<EngineApi> = {
            let auth = Auth::new(jwt_key, jwt_id, jwt_version);
            debug!(log, "Loaded execution endpoint"; "endpoint" => %execution_url, "jwt_path" => ?secret_file.as_path());
            let api = HttpJsonRpc::<EngineApi>::new_with_auth(execution_url, auth)
                .map_err(Error::ApiError)?;
            Engine::<EngineApi>::new(api)
        };

        let builder = builder_url
            .map(|url| BuilderHttpClient::new(url).map_err(Error::Builder))
            .transpose()?;

        let inner = Inner {
            engines: Engines {
                engine,
                latest_forkchoice_state: <_>::default(),
                log: log.clone(),
            },
            builder,
            execution_engine_forkchoice_lock: <_>::default(),
            suggested_fee_recipient,
            proposer_preparation_data: Mutex::new(HashMap::new()),
            proposers: RwLock::new(HashMap::new()),
            execution_blocks: Mutex::new(LruCache::new(EXECUTION_BLOCKS_LRU_CACHE_SIZE)),
            executor,
            phantom: std::marker::PhantomData,
            log,
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl<T: EthSpec> ExecutionLayer<T> {
    fn engines(&self) -> &Engines {
        &self.inner.engines
    }

    pub fn builder(&self) -> &Option<BuilderHttpClient> {
        &self.inner.builder
    }

    pub fn executor(&self) -> &TaskExecutor {
        &self.inner.executor
    }

    /// Note: this function returns a mutex guard, be careful to avoid deadlocks.
    async fn execution_blocks(
        &self,
    ) -> MutexGuard<'_, LruCache<ExecutionBlockHash, ExecutionBlock>> {
        self.inner.execution_blocks.lock().await
    }

    /// Note: this function returns a mutex guard, be careful to avoid deadlocks.
    async fn proposer_preparation_data(
        &self,
    ) -> MutexGuard<'_, HashMap<u64, ProposerPreparationDataEntry>> {
        self.inner.proposer_preparation_data.lock().await
    }

    fn proposers(&self) -> &RwLock<HashMap<ProposerKey, Proposer>> {
        &self.inner.proposers
    }

    fn log(&self) -> &Logger {
        &self.inner.log
    }

    pub async fn execution_engine_forkchoice_lock(&self) -> MutexGuard<'_, ()> {
        self.inner.execution_engine_forkchoice_lock.lock().await
    }

    /// Convenience function to allow spawning a task without waiting for the result.
    pub fn spawn<F, U>(&self, generate_future: F, name: &'static str)
    where
        F: FnOnce(Self) -> U,
        U: Future<Output = ()> + Send + 'static,
    {
        self.executor().spawn(generate_future(self.clone()), name);
    }

    /// Spawns a routine which attempts to keep the execution engines online.
    pub fn spawn_watchdog_routine<S: SlotClock + 'static>(&self, slot_clock: S) {
        let watchdog = |el: ExecutionLayer<T>| async move {
            // Run one task immediately.
            el.watchdog_task().await;

            let recurring_task =
                |el: ExecutionLayer<T>, now: Instant, duration_to_next_slot: Duration| async move {
                    // We run the task three times per slot.
                    //
                    // The interval between each task is 1/3rd of the slot duration. This matches nicely
                    // with the attestation production times (unagg. at 1/3rd, agg at 2/3rd).
                    //
                    // Each task is offset by 3/4ths of the interval.
                    //
                    // On mainnet, this means we will run tasks at:
                    //
                    // - 3s after slot start: 1s before publishing unaggregated attestations.
                    // - 7s after slot start: 1s before publishing aggregated attestations.
                    // - 11s after slot start: 1s before the next slot starts.
                    let interval = duration_to_next_slot / 3;
                    let offset = (interval / 4) * 3;

                    let first_execution = duration_to_next_slot + offset;
                    let second_execution = first_execution + interval;
                    let third_execution = second_execution + interval;

                    sleep_until(now + first_execution).await;
                    el.engines().upcheck_not_synced(Logging::Disabled).await;

                    sleep_until(now + second_execution).await;
                    el.engines().upcheck_not_synced(Logging::Disabled).await;

                    sleep_until(now + third_execution).await;
                    el.engines().upcheck_not_synced(Logging::Disabled).await;
                };

            // Start the loop to periodically update.
            loop {
                if let Some(duration) = slot_clock.duration_to_next_slot() {
                    let now = Instant::now();

                    // Spawn a new task rather than waiting for this to finish. This ensure that a
                    // slow run doesn't prevent the next run from starting.
                    el.spawn(|el| recurring_task(el, now, duration), "exec_watchdog_task");
                } else {
                    error!(el.log(), "Failed to spawn watchdog task");
                }
                sleep(slot_clock.slot_duration()).await;
            }
        };

        self.spawn(watchdog, "exec_watchdog");
    }

    /// Performs a single execution of the watchdog routine.
    pub async fn watchdog_task(&self) {
        // Disable logging since this runs frequently and may get annoying.
        self.engines().upcheck_not_synced(Logging::Disabled).await;
    }

    /// Spawns a routine which cleans the cached proposer data periodically.
    pub fn spawn_clean_proposer_caches_routine<S: SlotClock + 'static>(&self, slot_clock: S) {
        let preparation_cleaner = |el: ExecutionLayer<T>| async move {
            // Start the loop to periodically clean proposer preparation cache.
            loop {
                if let Some(duration_to_next_epoch) =
                    slot_clock.duration_to_next_epoch(T::slots_per_epoch())
                {
                    // Wait for next epoch
                    sleep(duration_to_next_epoch).await;

                    match slot_clock
                        .now()
                        .map(|slot| slot.epoch(T::slots_per_epoch()))
                    {
                        Some(current_epoch) => el
                            .clean_proposer_caches(current_epoch)
                            .await
                            .map_err(|e| {
                                error!(
                                    el.log(),
                                    "Failed to clean proposer preparation cache";
                                    "error" => format!("{:?}", e)
                                )
                            })
                            .unwrap_or(()),
                        None => error!(el.log(), "Failed to get current epoch from slot clock"),
                    }
                } else {
                    error!(el.log(), "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot and retry.
                    sleep(slot_clock.slot_duration()).await;
                }
            }
        };

        self.spawn(preparation_cleaner, "exec_preparation_cleanup");
    }

    /// Spawns a routine that polls the `exchange_transition_configuration` endpoint.
    pub fn spawn_transition_configuration_poll(&self, spec: ChainSpec) {
        let routine = |el: ExecutionLayer<T>| async move {
            loop {
                if let Err(e) = el.exchange_transition_configuration(&spec).await {
                    error!(
                        el.log(),
                        "Failed to check transition config";
                        "error" => ?e
                    );
                }
                sleep(CONFIG_POLL_INTERVAL).await;
            }
        };

        self.spawn(routine, "exec_config_poll");
    }

    /// Returns `true` if there is at least one synced and reachable engine.
    pub async fn is_synced(&self) -> bool {
        self.engines().is_synced().await
    }

    /// Updates the proposer preparation data provided by validators
    pub async fn update_proposer_preparation(
        &self,
        update_epoch: Epoch,
        preparation_data: &[ProposerPreparationData],
    ) {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;
        for preparation_entry in preparation_data {
            let new = ProposerPreparationDataEntry {
                update_epoch,
                preparation_data: preparation_entry.clone(),
            };

            let existing =
                proposer_preparation_data.insert(preparation_entry.validator_index, new.clone());

            if existing != Some(new) {
                metrics::inc_counter(&metrics::EXECUTION_LAYER_PROPOSER_DATA_UPDATED);
            }
        }
    }

    /// Removes expired entries from proposer_preparation_data and proposers caches
    async fn clean_proposer_caches(&self, current_epoch: Epoch) -> Result<(), Error> {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;

        // Keep all entries that have been updated in the last 2 epochs
        let retain_epoch = current_epoch.saturating_sub(Epoch::new(2));
        proposer_preparation_data.retain(|_validator_index, preparation_entry| {
            preparation_entry.update_epoch >= retain_epoch
        });
        drop(proposer_preparation_data);

        let retain_slot = retain_epoch.start_slot(T::slots_per_epoch());
        self.proposers()
            .write()
            .await
            .retain(|proposer_key, _proposer| proposer_key.slot >= retain_slot);

        Ok(())
    }

    /// Returns `true` if there have been any validators registered via
    /// `Self::update_proposer_preparation`.
    pub async fn has_any_proposer_preparation_data(&self) -> bool {
        !self.proposer_preparation_data().await.is_empty()
    }

    /// Returns `true` if the `proposer_index` has registered as a local validator via
    /// `Self::update_proposer_preparation`.
    pub async fn has_proposer_preparation_data(&self, proposer_index: u64) -> bool {
        self.proposer_preparation_data()
            .await
            .contains_key(&proposer_index)
    }

    /// Returns the fee-recipient address that should be used to build a block
    pub async fn get_suggested_fee_recipient(&self, proposer_index: u64) -> Address {
        if let Some(preparation_data_entry) =
            self.proposer_preparation_data().await.get(&proposer_index)
        {
            if let Some(suggested_fee_recipient) = self.inner.suggested_fee_recipient {
                if preparation_data_entry.preparation_data.fee_recipient != suggested_fee_recipient
                {
                    warn!(
                        self.log(),
                        "Inconsistent fee recipient";
                        "msg" => "The fee recipient returned from the Execution Engine differs \
                        from the suggested_fee_recipient set on the beacon node. This could \
                        indicate that fees are being diverted to another address. Please \
                        ensure that the value of suggested_fee_recipient is set correctly and \
                        that the Execution Engine is trusted.",
                        "proposer_index" => ?proposer_index,
                        "fee_recipient" => ?preparation_data_entry.preparation_data.fee_recipient,
                        "suggested_fee_recipient" => ?suggested_fee_recipient,
                    )
                }
            }
            // The values provided via the API have first priority.
            preparation_data_entry.preparation_data.fee_recipient
        } else if let Some(address) = self.inner.suggested_fee_recipient {
            // If there has been no fee recipient provided via the API, but the BN has been provided
            // with a global default address, use that.
            address
        } else {
            // If there is no user-provided fee recipient, use a junk value and complain loudly.
            crit!(
                self.log(),
                "Fee recipient unknown";
                "msg" => "the suggested_fee_recipient was unknown during block production. \
                a junk address was used, rewards were lost! \
                check the --suggested-fee-recipient flag and VC configuration.",
                "proposer_index" => ?proposer_index
            );

            Address::from_slice(&DEFAULT_SUGGESTED_FEE_RECIPIENT)
        }
    }

    /// Maps to the `engine_getPayload` JSON-RPC call.
    ///
    /// However, it will attempt to call `self.prepare_payload` if it cannot find an existing
    /// payload id for the given parameters.
    ///
    /// ## Fallback Behavior
    ///
    /// The result will be returned from the first node that returns successfully. No more nodes
    /// will be contacted.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_payload<Payload: ExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        finalized_block_hash: ExecutionBlockHash,
        proposer_index: u64,
        pubkey: Option<PublicKeyBytes>,
        slot: Slot,
    ) -> Result<Payload, Error> {
        let suggested_fee_recipient = self.get_suggested_fee_recipient(proposer_index).await;

        match Payload::block_type() {
            BlockType::Blinded => {
                let _timer = metrics::start_timer_vec(
                    &metrics::EXECUTION_LAYER_REQUEST_TIMES,
                    &[metrics::GET_BLINDED_PAYLOAD],
                );
                self.get_blinded_payload(
                    parent_hash,
                    timestamp,
                    prev_randao,
                    finalized_block_hash,
                    suggested_fee_recipient,
                    pubkey,
                    slot,
                )
                .await
            }
            BlockType::Full => {
                let _timer = metrics::start_timer_vec(
                    &metrics::EXECUTION_LAYER_REQUEST_TIMES,
                    &[metrics::GET_PAYLOAD],
                );
                self.get_full_payload(
                    parent_hash,
                    timestamp,
                    prev_randao,
                    finalized_block_hash,
                    suggested_fee_recipient,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_blinded_payload<Payload: ExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        finalized_block_hash: ExecutionBlockHash,
        suggested_fee_recipient: Address,
        pubkey_opt: Option<PublicKeyBytes>,
        slot: Slot,
    ) -> Result<Payload, Error> {
        //FIXME(sean) fallback logic included in PR #3134

        // Don't attempt to outsource payload construction until after the merge transition has been
        // finalized. We want to be conservative with payload construction until then.
        if let (Some(builder), Some(pubkey)) = (self.builder(), pubkey_opt) {
            if finalized_block_hash != ExecutionBlockHash::zero() {
                info!(
                    self.log(),
                    "Requesting blinded header from connected builder";
                    "slot" => ?slot,
                    "pubkey" => ?pubkey,
                    "parent_hash" => ?parent_hash,
                );
                return builder
                    .get_builder_header::<T, Payload>(slot, parent_hash, &pubkey)
                    .await
                    .map(|d| d.data.message.header)
                    .map_err(Error::Builder);
            }
        }
        self.get_full_payload::<Payload>(
            parent_hash,
            timestamp,
            prev_randao,
            finalized_block_hash,
            suggested_fee_recipient,
        )
        .await
    }

    /// Get a full payload without caching its result in the execution layer's payload cache.
    async fn get_full_payload<Payload: ExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        finalized_block_hash: ExecutionBlockHash,
        suggested_fee_recipient: Address,
    ) -> Result<Payload, Error> {
        self.get_full_payload_with(
            parent_hash,
            timestamp,
            prev_randao,
            finalized_block_hash,
            suggested_fee_recipient,
            noop,
        )
        .await
    }

    async fn get_full_payload_with<Payload: ExecPayload<T>>(
        &self,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        finalized_block_hash: ExecutionBlockHash,
        suggested_fee_recipient: Address,
        f: fn(&ExecutionLayer<T>, &ExecutionPayload<T>) -> Option<ExecutionPayload<T>>,
    ) -> Result<Payload, Error> {
        debug!(
            self.log(),
            "Issuing engine_getPayload";
            "suggested_fee_recipient" => ?suggested_fee_recipient,
            "prev_randao" => ?prev_randao,
            "timestamp" => timestamp,
            "parent_hash" => ?parent_hash,
        );
        self.engines()
            .first_success(|engine| async move {
                let payload_id = if let Some(id) = engine
                    .get_payload_id(parent_hash, timestamp, prev_randao, suggested_fee_recipient)
                    .await
                {
                    // The payload id has been cached for this engine.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::HIT],
                    );
                    id
                } else {
                    // The payload id has *not* been cached for this engine. Trigger an artificial
                    // fork choice update to retrieve a payload ID.
                    //
                    // TODO(merge): a better algorithm might try to favour a node that already had a
                    // cached payload id, since a payload that has had more time to produce is
                    // likely to be more profitable.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::MISS],
                    );
                    let fork_choice_state = ForkChoiceState {
                        head_block_hash: parent_hash,
                        safe_block_hash: parent_hash,
                        finalized_block_hash,
                    };
                    let payload_attributes = PayloadAttributes {
                        timestamp,
                        prev_randao,
                        suggested_fee_recipient,
                    };

                            let response = engine
                                .notify_forkchoice_updated(
                                    fork_choice_state,
                                    Some(payload_attributes),
                                    self.log(),
                                )
                                .await?;

                            match response.payload_id {
                                Some(payload_id) => payload_id,
                                None => {
                                    error!(
                                        self.log(),
                                        "Exec engine unable to produce payload";
                                        "msg" => "No payload ID, the engine is likely syncing. \
                                                  This has the potential to cause a missed block \
                                                  proposal.",
                                        "status" => ?response.payload_status
                                    );
                                    return Err(ApiError::PayloadIdUnavailable);
                                }
                            }
                        };

                engine
                    .api
                    .get_payload_v1::<T>(payload_id)
                    .await
                    .map(|full_payload| {
                        if f(self, &full_payload).is_some() {
                            warn!(self.log(), "Duplicate payload cached, this might indicate redundant proposal attempts.");
                        }
                        full_payload.into()
                    })
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Maps to the `engine_newPayload` JSON-RPC call.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Error::ConsensusFailure if some nodes return valid and some return invalid
    /// - Valid, if any nodes return valid.
    /// - Invalid, if any nodes return invalid.
    /// - Syncing, if any nodes return syncing.
    /// - An error, if all nodes return an error.
    pub async fn notify_new_payload(
        &self,
        execution_payload: &ExecutionPayload<T>,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::NEW_PAYLOAD],
        );

        trace!(
            self.log(),
            "Issuing engine_newPayload";
            "parent_hash" => ?execution_payload.parent_hash,
            "block_hash" => ?execution_payload.block_hash,
            "block_number" => execution_payload.block_number,
        );

        let broadcast_result = self
            .engines()
            .broadcast(|engine| engine.api.new_payload_v1(execution_payload.clone()))
            .await;

        process_payload_status(execution_payload.block_hash, broadcast_result, self.log())
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Register that the given `validator_index` is going to produce a block at `slot`.
    ///
    /// The block will be built atop `head_block_root` and the EL will need to prepare an
    /// `ExecutionPayload` as defined by the given `payload_attributes`.
    pub async fn insert_proposer(
        &self,
        slot: Slot,
        head_block_root: Hash256,
        validator_index: u64,
        payload_attributes: PayloadAttributes,
    ) -> bool {
        let proposers_key = ProposerKey {
            slot,
            head_block_root,
        };

        let existing = self.proposers().write().await.insert(
            proposers_key,
            Proposer {
                validator_index,
                payload_attributes,
            },
        );

        if existing.is_none() {
            metrics::inc_counter(&metrics::EXECUTION_LAYER_PROPOSER_INSERTED);
        }

        existing.is_some()
    }

    /// If there has been a proposer registered via `Self::insert_proposer` with a matching `slot`
    /// `head_block_root`, then return the appropriate `PayloadAttributes` for inclusion in
    /// `forkchoiceUpdated` calls.
    pub async fn payload_attributes(
        &self,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Option<PayloadAttributes> {
        let proposers_key = ProposerKey {
            slot: current_slot,
            head_block_root,
        };

        let proposer = self.proposers().read().await.get(&proposers_key).cloned()?;

        debug!(
            self.log(),
            "Beacon proposer found";
            "payload_attributes" => ?proposer.payload_attributes,
            "head_block_root" => ?head_block_root,
            "slot" => current_slot,
            "validator_index" => proposer.validator_index,
        );

        Some(proposer.payload_attributes)
    }

    /// Maps to the `engine_consensusValidated` JSON-RPC call.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Error::ConsensusFailure if some nodes return valid and some return invalid
    /// - Valid, if any nodes return valid.
    /// - Invalid, if any nodes return invalid.
    /// - Syncing, if any nodes return syncing.
    /// - An error, if all nodes return an error.
    pub async fn notify_forkchoice_updated(
        &self,
        head_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::FORKCHOICE_UPDATED],
        );

        trace!(
            self.log(),
            "Issuing engine_forkchoiceUpdated";
            "finalized_block_hash" => ?finalized_block_hash,
            "head_block_hash" => ?head_block_hash,
        );

        let next_slot = current_slot + 1;
        let payload_attributes = self.payload_attributes(next_slot, head_block_root).await;

        // Compute the "lookahead", the time between when the payload will be produced and now.
        if let Some(payload_attributes) = payload_attributes {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let timestamp = Duration::from_secs(payload_attributes.timestamp);
                if let Some(lookahead) = timestamp.checked_sub(now) {
                    metrics::observe_duration(
                        &metrics::EXECUTION_LAYER_PAYLOAD_ATTRIBUTES_LOOKAHEAD,
                        lookahead,
                    );
                } else {
                    debug!(
                        self.log(),
                        "Late payload attributes";
                        "timestamp" => ?timestamp,
                        "now" => ?now,
                    )
                }
            }
        }

        // see https://hackmd.io/@n0ble/kintsugi-spec#Engine-API
        // for now, we must set safe_block_hash = head_block_hash
        let forkchoice_state = ForkChoiceState {
            head_block_hash,
            safe_block_hash: head_block_hash,
            finalized_block_hash,
        };

        self.engines()
            .set_latest_forkchoice_state(forkchoice_state)
            .await;

        let broadcast_result = self
            .engines()
            .broadcast(|engine| async move {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes, self.log())
                    .await
            })
            .await;

        process_payload_status(
            head_block_hash,
            broadcast_result.map(|response| response.payload_status),
            self.log(),
        )
        .map_err(Box::new)
        .map_err(Error::EngineError)
    }

    pub async fn exchange_transition_configuration(&self, spec: &ChainSpec) -> Result<(), Error> {
        let local = TransitionConfigurationV1 {
            terminal_total_difficulty: spec.terminal_total_difficulty,
            terminal_block_hash: spec.terminal_block_hash,
            terminal_block_number: 0,
        };

        let broadcast_result = self
            .engines()
            .broadcast(|engine| engine.api.exchange_transition_configuration_v1(local))
            .await;

        match broadcast_result {
            Ok(remote) => {
                if local.terminal_total_difficulty != remote.terminal_total_difficulty
                    || local.terminal_block_hash != remote.terminal_block_hash
                {
                    error!(
                        self.log(),
                        "Execution client config mismatch";
                        "msg" => "ensure lighthouse and the execution client are up-to-date and \
                                  configured consistently",
                        "remote" => ?remote,
                        "local" => ?local,
                    );
                    Err(Error::EngineError(Box::new(EngineError::Api {
                        error: ApiError::TransitionConfigurationMismatch,
                    })))
                } else {
                    debug!(
                        self.log(),
                        "Execution client config is OK";
                    );
                    Ok(())
                }
            }
            Err(e) => {
                error!(
                    self.log(),
                    "Unable to get transition config";
                    "error" => ?e,
                );
                Err(Error::EngineError(Box::new(e)))
            }
        }
    }

    /// Used during block production to determine if the merge has been triggered.
    ///
    /// ## Specification
    ///
    /// `get_terminal_pow_block_hash`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md
    pub async fn get_terminal_pow_block_hash(
        &self,
        spec: &ChainSpec,
    ) -> Result<Option<ExecutionBlockHash>, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::GET_TERMINAL_POW_BLOCK_HASH],
        );

        let hash_opt = self
            .engines()
            .first_success(|engine| async move {
                let terminal_block_hash = spec.terminal_block_hash;
                if terminal_block_hash != ExecutionBlockHash::zero() {
                    if self
                        .get_pow_block(engine, terminal_block_hash)
                        .await?
                        .is_some()
                    {
                        return Ok(Some(terminal_block_hash));
                    } else {
                        return Ok(None);
                    }
                }

                self.get_pow_block_hash_at_total_difficulty(engine, spec)
                    .await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)?;

        if let Some(hash) = &hash_opt {
            info!(
                self.log(),
                "Found terminal block hash";
                "terminal_block_hash_override" => ?spec.terminal_block_hash,
                "terminal_total_difficulty" => ?spec.terminal_total_difficulty,
                "block_hash" => ?hash,
            );
        }

        Ok(hash_opt)
    }

    /// This function should remain internal. External users should use
    /// `self.get_terminal_pow_block` instead, since it checks against the terminal block hash
    /// override.
    ///
    /// ## Specification
    ///
    /// `get_pow_block_at_terminal_total_difficulty`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md
    async fn get_pow_block_hash_at_total_difficulty(
        &self,
        engine: &Engine<EngineApi>,
        spec: &ChainSpec,
    ) -> Result<Option<ExecutionBlockHash>, ApiError> {
        let mut block = engine
            .api
            .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
            .await?
            .ok_or(ApiError::ExecutionHeadBlockNotFound)?;

        self.execution_blocks().await.put(block.block_hash, block);

        loop {
            let block_reached_ttd = block.total_difficulty >= spec.terminal_total_difficulty;
            if block_reached_ttd {
                if block.parent_hash == ExecutionBlockHash::zero() {
                    return Ok(Some(block.block_hash));
                }
                let parent = self
                    .get_pow_block(engine, block.parent_hash)
                    .await?
                    .ok_or(ApiError::ExecutionBlockNotFound(block.parent_hash))?;
                let parent_reached_ttd = parent.total_difficulty >= spec.terminal_total_difficulty;

                if block_reached_ttd && !parent_reached_ttd {
                    return Ok(Some(block.block_hash));
                } else {
                    block = parent;
                }
            } else {
                return Ok(None);
            }
        }
    }

    /// Used during block verification to check that a block correctly triggers the merge.
    ///
    /// ## Returns
    ///
    /// - `Some(true)` if the given `block_hash` is the terminal proof-of-work block.
    /// - `Some(false)` if the given `block_hash` is certainly *not* the terminal proof-of-work
    ///     block.
    /// - `None` if the `block_hash` or its parent were not present on the execution engines.
    /// - `Err(_)` if there was an error connecting to the execution engines.
    ///
    /// ## Fallback Behaviour
    ///
    /// The request will be broadcast to all nodes, simultaneously. It will await a response (or
    /// failure) from all nodes and then return based on the first of these conditions which
    /// returns true:
    ///
    /// - Terminal, if any node indicates it is terminal.
    /// - Not terminal, if any node indicates it is non-terminal.
    /// - Block not found, if any node cannot find the block.
    /// - An error, if all nodes return an error.
    ///
    /// ## Specification
    ///
    /// `is_valid_terminal_pow_block`
    ///
    /// https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/fork-choice.md
    pub async fn is_valid_terminal_pow_block_hash(
        &self,
        block_hash: ExecutionBlockHash,
        spec: &ChainSpec,
    ) -> Result<Option<bool>, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::IS_VALID_TERMINAL_POW_BLOCK_HASH],
        );

        self.engines()
            .broadcast(|engine| async move {
                if let Some(pow_block) = self.get_pow_block(engine, block_hash).await? {
                    if let Some(pow_parent) =
                        self.get_pow_block(engine, pow_block.parent_hash).await?
                    {
                        return Ok(Some(
                            self.is_valid_terminal_pow_block(pow_block, pow_parent, spec),
                        ));
                    }
                }
                Ok(None)
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// This function should remain internal.
    ///
    /// External users should use `self.is_valid_terminal_pow_block_hash`.
    fn is_valid_terminal_pow_block(
        &self,
        block: ExecutionBlock,
        parent: ExecutionBlock,
        spec: &ChainSpec,
    ) -> bool {
        let is_total_difficulty_reached = block.total_difficulty >= spec.terminal_total_difficulty;
        let is_parent_total_difficulty_valid =
            parent.total_difficulty < spec.terminal_total_difficulty;
        is_total_difficulty_reached && is_parent_total_difficulty_valid
    }

    /// Maps to the `eth_getBlockByHash` JSON-RPC call.
    ///
    /// ## TODO(merge)
    ///
    /// This will return an execution block regardless of whether or not it was created by a PoW
    /// miner (pre-merge) or a PoS validator (post-merge). It's not immediately clear if this is
    /// correct or not, see the discussion here:
    ///
    /// https://github.com/ethereum/consensus-specs/issues/2636
    async fn get_pow_block(
        &self,
        engine: &Engine<EngineApi>,
        hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
        if let Some(cached) = self.execution_blocks().await.get(&hash).copied() {
            // The block was in the cache, no need to request it from the execution
            // engine.
            return Ok(Some(cached));
        }

        // The block was *not* in the cache, request it from the execution
        // engine and cache it for future reference.
        if let Some(block) = engine.api.get_block_by_hash(hash).await? {
            self.execution_blocks().await.put(hash, block);
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub async fn get_payload_by_block_hash(
        &self,
        hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionPayload<T>>, Error> {
        self.engines()
            .first_success(|engine| async move {
                self.get_payload_by_block_hash_from_engine(engine, hash)
                    .await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    async fn get_payload_by_block_hash_from_engine(
        &self,
        engine: &Engine<EngineApi>,
        hash: ExecutionBlockHash,
    ) -> Result<Option<ExecutionPayload<T>>, ApiError> {
        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_GET_PAYLOAD_BY_BLOCK_HASH);

        if hash == ExecutionBlockHash::zero() {
            return Ok(Some(ExecutionPayload::default()));
        }

        let block = if let Some(block) = engine.api.get_block_by_hash_with_txns::<T>(hash).await? {
            block
        } else {
            return Ok(None);
        };

        let transactions = VariableList::new(
            block
                .transactions
                .into_iter()
                .map(|transaction| VariableList::new(transaction.rlp().to_vec()))
                .collect::<Result<_, _>>()
                .map_err(ApiError::DeserializeTransaction)?,
        )
        .map_err(ApiError::DeserializeTransactions)?;

        Ok(Some(ExecutionPayload {
            parent_hash: block.parent_hash,
            fee_recipient: block.fee_recipient,
            state_root: block.state_root,
            receipts_root: block.receipts_root,
            logs_bloom: block.logs_bloom,
            prev_randao: block.prev_randao,
            block_number: block.block_number,
            gas_limit: block.gas_limit,
            gas_used: block.gas_used,
            timestamp: block.timestamp,
            extra_data: block.extra_data,
            base_fee_per_gas: block.base_fee_per_gas,
            block_hash: block.block_hash,
            transactions,
        }))
    }

    pub async fn propose_blinded_beacon_block(
        &self,
        block: &SignedBeaconBlock<T, BlindedPayload<T>>,
    ) -> Result<ExecutionPayload<T>, Error> {
        debug!(
            self.log(),
            "Sending block to builder";
            "root" => ?block.canonical_root(),
        );
        if let Some(builder) = self.builder() {
            builder
                .post_builder_blinded_blocks(block)
                .await
                .map_err(Error::Builder)
                .map(|d| d.data)
        } else {
            Err(Error::NoPayloadBuilder)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockExecutionLayer as GenericMockExecutionLayer;
    use task_executor::test_utils::TestRuntime;
    use types::MainnetEthSpec;

    type MockExecutionLayer = GenericMockExecutionLayer<MainnetEthSpec>;

    #[tokio::test]
    async fn produce_three_valid_pos_execution_blocks() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .produce_valid_execution_payload_on_head()
            .await
            .produce_valid_execution_payload_on_head()
            .await
            .produce_valid_execution_payload_on_head()
            .await;
    }

    #[tokio::test]
    async fn finds_valid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engines().upcheck_not_synced(Logging::Disabled).await;
                assert_eq!(el.get_terminal_pow_block_hash(&spec).await.unwrap(), None)
            })
            .await
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec).await.unwrap(),
                    Some(terminal_block.unwrap().block_hash)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn verifies_valid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                el.engines().upcheck_not_synced(Logging::Disabled).await;
                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(terminal_block.unwrap().block_hash, &spec)
                        .await
                        .unwrap(),
                    Some(true)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_invalid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                el.engines().upcheck_not_synced(Logging::Disabled).await;
                let invalid_terminal_block = terminal_block.unwrap().parent_hash;

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(invalid_terminal_block, &spec)
                        .await
                        .unwrap(),
                    Some(false)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_unknown_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engines().upcheck_not_synced(Logging::Disabled).await;
                let missing_terminal_block = ExecutionBlockHash::repeat_byte(42);

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(missing_terminal_block, &spec)
                        .await
                        .unwrap(),
                    None
                )
            })
            .await;
    }
}

fn noop<T: EthSpec>(_: &ExecutionLayer<T>, _: &ExecutionPayload<T>) -> Option<ExecutionPayload<T>> {
    None
}
