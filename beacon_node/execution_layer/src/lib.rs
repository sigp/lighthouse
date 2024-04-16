//! This crate provides an abstraction over one or more *execution engines*. An execution engine
//! was formerly known as an "eth1 node", like Geth, Nethermind, Erigon, etc.
//!
//! This crate only provides useful functionality for "The Merge", it does not provide any of the
//! deposit-contract functionality that the `beacon_node/eth1` crate already provides.

use crate::payload_cache::PayloadCache;
use arc_swap::ArcSwapOption;
use auth::{strip_prefix, Auth, JwtKey};
pub use block_hash::calculate_execution_block_hash;
use builder_client::BuilderHttpClient;
pub use engine_api::EngineCapabilities;
use engine_api::Error as ApiError;
pub use engine_api::*;
pub use engine_api::{http, http::deposit_methods, http::HttpJsonRpc};
use engines::{Engine, EngineError};
pub use engines::{EngineState, ForkchoiceState};
use eth2::types::FullPayloadContents;
use eth2::types::{builder_bid::SignedBuilderBid, BlobsBundle, ForkVersionedResponse};
use ethers_core::types::Transaction as EthersTransaction;
use fork_choice::ForkchoiceUpdateParameters;
use lru::LruCache;
use payload_status::process_payload_status;
pub use payload_status::PayloadStatus;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use strum::AsRefStr;
use task_executor::TaskExecutor;
use tokio::{
    sync::{Mutex, MutexGuard, RwLock},
    time::sleep,
};
use tokio_stream::wrappers::WatchStream;
use tree_hash::TreeHash;
use types::beacon_block_body::KzgCommitments;
use types::builder_bid::BuilderBid;
use types::non_zero_usize::new_non_zero_usize;
use types::payload::BlockProductionVersion;
use types::{
    AbstractExecPayload, BlobsList, ExecutionPayloadDeneb, KzgProofs, SignedBlindedBeaconBlock,
};
use types::{
    BeaconStateError, BlindedPayload, ChainSpec, Epoch, ExecPayload, ExecutionPayloadCapella,
    ExecutionPayloadMerge, FullPayload, ProposerPreparationData, PublicKeyBytes, Signature, Slot,
};

mod block_hash;
mod engine_api;
pub mod engines;
mod keccak;
mod metrics;
pub mod payload_cache;
mod payload_status;
pub mod test_utils;
mod versioned_hashes;

/// Indicates the default jwt authenticated execution endpoint.
pub const DEFAULT_EXECUTION_ENDPOINT: &str = "http://localhost:8551/";

/// Name for the default file used for the jwt secret.
pub const DEFAULT_JWT_FILE: &str = "jwt.hex";

/// Each time the `ExecutionLayer` retrieves a block from an execution node, it stores that block
/// in an LRU cache to avoid redundant lookups. This is the size of that cache.
const EXECUTION_BLOCKS_LRU_CACHE_SIZE: NonZeroUsize = new_non_zero_usize(128);

/// A fee recipient address for use during block production. Only used as a very last resort if
/// there is no address provided by the user.
///
/// ## Note
///
/// This is *not* the zero-address, since Geth has been known to return errors for a coinbase of
/// 0x00..00.
const DEFAULT_SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// A payload alongside some information about where it came from.
pub enum ProvenancedPayload<P> {
    /// A good old fashioned farm-to-table payload from your local EE.
    Local(P),
    /// A payload from a builder (e.g. mev-boost).
    Builder(P),
}

impl<E: EthSpec> TryFrom<BuilderBid<E>> for ProvenancedPayload<BlockProposalContentsType<E>> {
    type Error = Error;

    fn try_from(value: BuilderBid<E>) -> Result<Self, Error> {
        let block_proposal_contents = match value {
            BuilderBid::Merge(builder_bid) => BlockProposalContents::Payload {
                payload: ExecutionPayloadHeader::Merge(builder_bid.header).into(),
                block_value: builder_bid.value,
            },
            BuilderBid::Capella(builder_bid) => BlockProposalContents::Payload {
                payload: ExecutionPayloadHeader::Capella(builder_bid.header).into(),
                block_value: builder_bid.value,
            },
            BuilderBid::Deneb(builder_bid) => BlockProposalContents::PayloadAndBlobs {
                payload: ExecutionPayloadHeader::Deneb(builder_bid.header).into(),
                block_value: builder_bid.value,
                kzg_commitments: builder_bid.blob_kzg_commitments,
                blobs_and_proofs: None,
            },
        };
        Ok(ProvenancedPayload::Builder(
            BlockProposalContentsType::Blinded(block_proposal_contents),
        ))
    }
}

#[derive(Debug)]
pub enum Error {
    NoEngine,
    NoPayloadBuilder,
    ApiError(ApiError),
    Builder(builder_client::Error),
    NoHeaderFromBuilder,
    CannotProduceHeader,
    EngineError(Box<EngineError>),
    NotSynced,
    ShuttingDown,
    FeeRecipientUnspecified,
    MissingLatestValidHash,
    BlockHashMismatch {
        computed: ExecutionBlockHash,
        payload: ExecutionBlockHash,
        transactions_root: Hash256,
    },
    InvalidJWTSecret(String),
    InvalidForkForPayload,
    InvalidPayloadBody(String),
    InvalidPayloadConversion,
    InvalidBlobConversion(String),
    BeaconStateError(BeaconStateError),
    PayloadTypeMismatch,
    VerifyingVersionedHashes(versioned_hashes::Error),
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

pub enum BlockProposalContentsType<E: EthSpec> {
    Full(BlockProposalContents<E, FullPayload<E>>),
    Blinded(BlockProposalContents<E, BlindedPayload<E>>),
}

pub enum BlockProposalContents<T: EthSpec, Payload: AbstractExecPayload<T>> {
    Payload {
        payload: Payload,
        block_value: Uint256,
    },
    PayloadAndBlobs {
        payload: Payload,
        block_value: Uint256,
        kzg_commitments: KzgCommitments<T>,
        /// `None` for blinded `PayloadAndBlobs`.
        blobs_and_proofs: Option<(BlobsList<T>, KzgProofs<T>)>,
    },
}

impl<T: EthSpec> From<BlockProposalContents<T, FullPayload<T>>>
    for BlockProposalContents<T, BlindedPayload<T>>
{
    fn from(item: BlockProposalContents<T, FullPayload<T>>) -> Self {
        match item {
            BlockProposalContents::Payload {
                payload,
                block_value,
            } => BlockProposalContents::Payload {
                payload: payload.execution_payload().into(),
                block_value,
            },
            BlockProposalContents::PayloadAndBlobs {
                payload,
                block_value,
                kzg_commitments,
                blobs_and_proofs: _,
            } => BlockProposalContents::PayloadAndBlobs {
                payload: payload.execution_payload().into(),
                block_value,
                kzg_commitments,
                blobs_and_proofs: None,
            },
        }
    }
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> TryFrom<GetPayloadResponse<E>>
    for BlockProposalContents<E, Payload>
{
    type Error = Error;

    fn try_from(response: GetPayloadResponse<E>) -> Result<Self, Error> {
        let (execution_payload, block_value, maybe_bundle) = response.into();
        match maybe_bundle {
            Some(bundle) => Ok(Self::PayloadAndBlobs {
                payload: execution_payload.into(),
                block_value,
                kzg_commitments: bundle.commitments,
                blobs_and_proofs: Some((bundle.blobs, bundle.proofs)),
            }),
            None => Ok(Self::Payload {
                payload: execution_payload.into(),
                block_value,
            }),
        }
    }
}

impl<E: EthSpec> TryFrom<GetPayloadResponseType<E>> for BlockProposalContentsType<E> {
    type Error = Error;

    fn try_from(response_type: GetPayloadResponseType<E>) -> Result<Self, Error> {
        match response_type {
            GetPayloadResponseType::Full(response) => Ok(Self::Full(response.try_into()?)),
            GetPayloadResponseType::Blinded(response) => Ok(Self::Blinded(response.try_into()?)),
        }
    }
}

#[allow(clippy::type_complexity)]
impl<T: EthSpec, Payload: AbstractExecPayload<T>> BlockProposalContents<T, Payload> {
    pub fn deconstruct(
        self,
    ) -> (
        Payload,
        Option<KzgCommitments<T>>,
        Option<(BlobsList<T>, KzgProofs<T>)>,
        Uint256,
    ) {
        match self {
            Self::Payload {
                payload,
                block_value,
            } => (payload, None, None, block_value),
            Self::PayloadAndBlobs {
                payload,
                block_value,
                kzg_commitments,
                blobs_and_proofs,
            } => (
                payload,
                Some(kzg_commitments),
                blobs_and_proofs,
                block_value,
            ),
        }
    }

    pub fn payload(&self) -> &Payload {
        match self {
            Self::Payload { payload, .. } => payload,
            Self::PayloadAndBlobs { payload, .. } => payload,
        }
    }
    pub fn to_payload(self) -> Payload {
        match self {
            Self::Payload { payload, .. } => payload,
            Self::PayloadAndBlobs { payload, .. } => payload,
        }
    }
    pub fn block_value(&self) -> &Uint256 {
        match self {
            Self::Payload { block_value, .. } => block_value,
            Self::PayloadAndBlobs { block_value, .. } => block_value,
        }
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

/// Information from the beacon chain that is necessary for querying the builder API.
pub struct BuilderParams {
    pub pubkey: PublicKeyBytes,
    pub slot: Slot,
    pub chain_health: ChainHealth,
}

#[derive(PartialEq)]
pub enum ChainHealth {
    Healthy,
    Unhealthy(FailedCondition),
    Optimistic,
    PreMerge,
}

#[derive(Debug, PartialEq)]
pub enum FailedCondition {
    Skips,
    SkipsPerEpoch,
    EpochsSinceFinalization,
}

type PayloadContentsRefTuple<'a, T> = (ExecutionPayloadRef<'a, T>, Option<&'a BlobsBundle<T>>);

struct Inner<E: EthSpec> {
    engine: Arc<Engine>,
    builder: ArcSwapOption<BuilderHttpClient>,
    execution_engine_forkchoice_lock: Mutex<()>,
    suggested_fee_recipient: Option<Address>,
    proposer_preparation_data: Mutex<HashMap<u64, ProposerPreparationDataEntry>>,
    execution_blocks: Mutex<LruCache<ExecutionBlockHash, ExecutionBlock>>,
    proposers: RwLock<HashMap<ProposerKey, Proposer>>,
    executor: TaskExecutor,
    payload_cache: PayloadCache<E>,
    log: Logger,
    /// Track whether the last `newPayload` call errored.
    ///
    /// This is used *only* in the informational sync status endpoint, so that a VC using this
    /// node can prefer another node with a healthier EL.
    last_new_payload_errored: RwLock<bool>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint url for EL nodes that are running the engine api.
    pub execution_endpoint: Option<SensitiveUrl>,
    /// Endpoint urls for services providing the builder api.
    pub builder_url: Option<SensitiveUrl>,
    /// User agent to send with requests to the builder API.
    pub builder_user_agent: Option<String>,
    /// JWT secret for the above endpoint running the engine api.
    pub secret_file: Option<PathBuf>,
    /// The default fee recipient to use on the beacon node if none if provided from
    /// the validator client during block preparation.
    pub suggested_fee_recipient: Option<Address>,
    /// An optional id for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_id: Option<String>,
    /// An optional client version for the beacon node that will be passed to the EL in the JWT token claim.
    pub jwt_version: Option<String>,
    /// Default directory for the jwt secret if not provided through cli.
    pub default_datadir: PathBuf,
    pub execution_timeout_multiplier: Option<u32>,
}

/// Provides access to one execution engine and provides a neat interface for consumption by the
/// `BeaconChain`.
#[derive(Clone)]
pub struct ExecutionLayer<T: EthSpec> {
    inner: Arc<Inner<T>>,
}

impl<T: EthSpec> ExecutionLayer<T> {
    /// Instantiate `Self` with an Execution engine specified in `Config`, using JSON-RPC via HTTP.
    pub fn from_config(config: Config, executor: TaskExecutor, log: Logger) -> Result<Self, Error> {
        let Config {
            execution_endpoint: url,
            builder_url,
            builder_user_agent,
            secret_file,
            suggested_fee_recipient,
            jwt_id,
            jwt_version,
            default_datadir,
            execution_timeout_multiplier,
        } = config;

        let execution_url = url.ok_or(Error::NoEngine)?;

        // Use the default jwt secret path if not provided via cli.
        let secret_file = secret_file.unwrap_or_else(|| default_datadir.join(DEFAULT_JWT_FILE));

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
            warn!(log, "No JWT found on disk. Generating"; "path" => %secret_file.display());
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

        let engine: Engine = {
            let auth = Auth::new(jwt_key, jwt_id, jwt_version);
            debug!(log, "Loaded execution endpoint"; "endpoint" => %execution_url, "jwt_path" => ?secret_file.as_path());
            let api = HttpJsonRpc::new_with_auth(execution_url, auth, execution_timeout_multiplier)
                .map_err(Error::ApiError)?;
            Engine::new(api, executor.clone(), &log)
        };

        let inner = Inner {
            engine: Arc::new(engine),
            builder: ArcSwapOption::empty(),
            execution_engine_forkchoice_lock: <_>::default(),
            suggested_fee_recipient,
            proposer_preparation_data: Mutex::new(HashMap::new()),
            proposers: RwLock::new(HashMap::new()),
            execution_blocks: Mutex::new(LruCache::new(EXECUTION_BLOCKS_LRU_CACHE_SIZE)),
            executor,
            payload_cache: PayloadCache::default(),
            log,
            last_new_payload_errored: RwLock::new(false),
        };

        let el = Self {
            inner: Arc::new(inner),
        };

        if let Some(builder_url) = builder_url {
            el.set_builder_url(builder_url, builder_user_agent)?;
        }

        Ok(el)
    }

    fn engine(&self) -> &Arc<Engine> {
        &self.inner.engine
    }

    pub fn builder(&self) -> Option<Arc<BuilderHttpClient>> {
        self.inner.builder.load_full()
    }

    /// Set the builder URL after initialization.
    ///
    /// This is useful for breaking circular dependencies between mock ELs and mock builders in
    /// tests.
    pub fn set_builder_url(
        &self,
        builder_url: SensitiveUrl,
        builder_user_agent: Option<String>,
    ) -> Result<(), Error> {
        let builder_client = BuilderHttpClient::new(builder_url.clone(), builder_user_agent)
            .map_err(Error::Builder)?;
        info!(
            self.log(),
            "Using external block builder";
            "builder_url" => ?builder_url,
            "local_user_agent" => builder_client.get_user_agent(),
        );
        self.inner.builder.swap(Some(Arc::new(builder_client)));
        Ok(())
    }

    /// Cache a full payload, keyed on the `tree_hash_root` of the payload
    fn cache_payload(
        &self,
        payload_and_blobs: PayloadContentsRefTuple<T>,
    ) -> Option<FullPayloadContents<T>> {
        let (payload_ref, maybe_json_blobs_bundle) = payload_and_blobs;

        let payload = payload_ref.clone_from_ref();
        let maybe_blobs_bundle = maybe_json_blobs_bundle
            .cloned()
            .map(|blobs_bundle| BlobsBundle {
                commitments: blobs_bundle.commitments,
                proofs: blobs_bundle.proofs,
                blobs: blobs_bundle.blobs,
            });

        self.inner
            .payload_cache
            .put(FullPayloadContents::new(payload, maybe_blobs_bundle))
    }

    /// Attempt to retrieve a full payload from the payload cache by the payload root
    pub fn get_payload_by_root(&self, root: &Hash256) -> Option<FullPayloadContents<T>> {
        self.inner.payload_cache.get(root)
    }

    pub fn executor(&self) -> &TaskExecutor {
        &self.inner.executor
    }

    /// Get the current difficulty of the PoW chain.
    pub async fn get_current_difficulty(&self) -> Result<Uint256, ApiError> {
        let block = self
            .engine()
            .api
            .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
            .await?
            .ok_or(ApiError::ExecutionHeadBlockNotFound)?;
        Ok(block.total_difficulty)
    }
    /// Note: this function returns a mutex guard, be careful to avoid deadlocks.
    async fn execution_blocks(
        &self,
    ) -> MutexGuard<'_, LruCache<ExecutionBlockHash, ExecutionBlock>> {
        self.inner.execution_blocks.lock().await
    }

    /// Gives access to a channel containing if the last engine state is online or not.
    ///
    /// This can be called several times.
    pub async fn get_responsiveness_watch(&self) -> WatchStream<EngineState> {
        self.engine().watch_state().await
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

    /// Spawns a routine which attempts to keep the execution engine online.
    pub fn spawn_watchdog_routine<S: SlotClock + 'static>(&self, slot_clock: S) {
        let watchdog = |el: ExecutionLayer<T>| async move {
            // Run one task immediately.
            el.watchdog_task().await;

            // Start the loop to periodically update.
            loop {
                el.spawn(
                    |el| async move { el.watchdog_task().await },
                    "exec_watchdog_task",
                );
                sleep(slot_clock.slot_duration()).await;
            }
        };

        self.spawn(watchdog, "exec_watchdog");
    }

    /// Performs a single execution of the watchdog routine.
    pub async fn watchdog_task(&self) {
        self.engine().upcheck().await;
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

    /// Returns `true` if the execution engine is synced and reachable.
    pub async fn is_synced(&self) -> bool {
        self.engine().is_synced().await
    }

    /// Execution nodes return a "SYNCED" response when they do not have any peers.
    ///
    /// This function is a wrapper over `Self::is_synced` that makes an additional
    /// check for the execution layer sync status. Checks if the latest block has
    /// a `block_number != 0` *if* the `current_slot` is also `> 0`.
    /// Returns the `Self::is_synced` response if unable to get latest block.
    pub async fn is_synced_for_notifier(&self, current_slot: Slot) -> bool {
        let synced = self.is_synced().await;
        if synced {
            if let Ok(Some(block)) = self
                .engine()
                .api
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
            {
                if block.block_number == 0 && current_slot > 0 {
                    return false;
                }
            }
        }
        synced
    }

    /// Return `true` if the execution layer is offline or returning errors on `newPayload`.
    ///
    /// This function should never be used to prevent any operation in the beacon node, but can
    /// be used to give an indication on the HTTP API that the node's execution layer is struggling,
    /// which can in turn be used by the VC.
    pub async fn is_offline_or_erroring(&self) -> bool {
        self.engine().is_offline().await || *self.inner.last_new_payload_errored.read().await
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

    /// Delete proposer preparation data for `proposer_index`. This is only useful in tests.
    pub async fn clear_proposer_preparation(&self, proposer_index: u64) {
        self.proposer_preparation_data()
            .await
            .remove(&proposer_index);
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

    /// Check if a proposer is registered as a local validator, *from a synchronous context*.
    ///
    /// This method MUST NOT be called from an async task.
    pub fn has_proposer_preparation_data_blocking(&self, proposer_index: u64) -> bool {
        self.inner
            .proposer_preparation_data
            .blocking_lock()
            .contains_key(&proposer_index)
    }

    /// Returns the fee-recipient address that should be used to build a block
    pub async fn get_suggested_fee_recipient(&self, proposer_index: u64) -> Address {
        if let Some(preparation_data_entry) =
            self.proposer_preparation_data().await.get(&proposer_index)
        {
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
    pub async fn get_payload(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        builder_params: BuilderParams,
        current_fork: ForkName,
        spec: &ChainSpec,
        builder_boost_factor: Option<u64>,
        block_production_version: BlockProductionVersion,
    ) -> Result<BlockProposalContentsType<T>, Error> {
        let payload_result_type = match block_production_version {
            BlockProductionVersion::V3 => match self
                .determine_and_fetch_payload(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    builder_params,
                    current_fork,
                    builder_boost_factor,
                    spec,
                )
                .await
            {
                Ok(payload) => payload,
                Err(e) => {
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                        &[metrics::FAILURE],
                    );
                    return Err(e);
                }
            },
            BlockProductionVersion::BlindedV2 => {
                let _timer = metrics::start_timer_vec(
                    &metrics::EXECUTION_LAYER_REQUEST_TIMES,
                    &[metrics::GET_BLINDED_PAYLOAD],
                );
                self.determine_and_fetch_payload(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    builder_params,
                    current_fork,
                    None,
                    spec,
                )
                .await?
            }
            BlockProductionVersion::FullV2 => self
                .get_full_payload_with(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    current_fork,
                    noop,
                )
                .await
                .and_then(GetPayloadResponseType::try_into)
                .map(ProvenancedPayload::Local)?,
        };

        let block_proposal_content_type = match payload_result_type {
            ProvenancedPayload::Local(local_payload) => local_payload,
            ProvenancedPayload::Builder(builder_payload) => builder_payload,
        };

        match block_proposal_content_type {
            BlockProposalContentsType::Full(block_proposal_contents) => {
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                    &[metrics::SUCCESS],
                );
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_SOURCE,
                    &[metrics::LOCAL],
                );
                if matches!(block_production_version, BlockProductionVersion::BlindedV2) {
                    Ok(BlockProposalContentsType::Blinded(
                        block_proposal_contents.into(),
                    ))
                } else {
                    Ok(BlockProposalContentsType::Full(block_proposal_contents))
                }
            }
            BlockProposalContentsType::Blinded(block_proposal_contents) => {
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_OUTCOME,
                    &[metrics::SUCCESS],
                );
                metrics::inc_counter_vec(
                    &metrics::EXECUTION_LAYER_GET_PAYLOAD_SOURCE,
                    &[metrics::BUILDER],
                );
                Ok(BlockProposalContentsType::Blinded(block_proposal_contents))
            }
        }
    }

    /// Fetches local and builder paylaods concurrently, Logs and returns results.
    async fn fetch_builder_and_local_payloads(
        &self,
        builder: &BuilderHttpClient,
        parent_hash: ExecutionBlockHash,
        builder_params: &BuilderParams,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
    ) -> (
        Result<Option<ForkVersionedResponse<SignedBuilderBid<T>>>, builder_client::Error>,
        Result<GetPayloadResponse<T>, Error>,
    ) {
        let slot = builder_params.slot;
        let pubkey = &builder_params.pubkey;

        info!(
            self.log(),
            "Requesting blinded header from connected builder";
            "slot" => ?slot,
            "pubkey" => ?pubkey,
            "parent_hash" => ?parent_hash,
        );

        // Wait for the builder *and* local EL to produce a payload (or return an error).
        let ((relay_result, relay_duration), (local_result, local_duration)) = tokio::join!(
            timed_future(metrics::GET_BLINDED_PAYLOAD_BUILDER, async {
                builder
                    .get_builder_header::<T>(slot, parent_hash, pubkey)
                    .await
            }),
            timed_future(metrics::GET_BLINDED_PAYLOAD_LOCAL, async {
                self.get_full_payload_caching(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    current_fork,
                )
                .await
                .and_then(|local_result_type| match local_result_type {
                    GetPayloadResponseType::Full(payload) => Ok(payload),
                    GetPayloadResponseType::Blinded(_) => Err(Error::PayloadTypeMismatch),
                })
            })
        );

        info!(
            self.log(),
            "Requested blinded execution payload";
            "relay_fee_recipient" => match &relay_result {
                Ok(Some(r)) => format!("{:?}", r.data.message.header().fee_recipient()),
                Ok(None) => "empty response".to_string(),
                Err(_) => "request failed".to_string(),
            },
            "relay_response_ms" => relay_duration.as_millis(),
            "local_fee_recipient" => match &local_result {
                Ok(get_payload_response) => format!("{:?}", get_payload_response.fee_recipient()),
                Err(_) => "request failed".to_string()
            },
            "local_response_ms" => local_duration.as_millis(),
            "parent_hash" => ?parent_hash,
        );

        (relay_result, local_result)
    }

    #[allow(clippy::too_many_arguments)]
    async fn determine_and_fetch_payload(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        builder_params: BuilderParams,
        current_fork: ForkName,
        builder_boost_factor: Option<u64>,
        spec: &ChainSpec,
    ) -> Result<ProvenancedPayload<BlockProposalContentsType<T>>, Error> {
        let Some(builder) = self.builder() else {
            // no builder.. return local payload
            return self
                .get_full_payload_caching(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    current_fork,
                )
                .await
                .and_then(GetPayloadResponseType::try_into)
                .map(ProvenancedPayload::Local);
        };

        // check chain health
        if builder_params.chain_health != ChainHealth::Healthy {
            // chain is unhealthy, gotta use local payload
            match builder_params.chain_health {
                ChainHealth::Unhealthy(condition) => info!(
                    self.log(),
                    "Chain is unhealthy, using local payload";
                    "info" => "this helps protect the network. the --builder-fallback flags \
                        can adjust the expected health conditions.",
                    "failed_condition" => ?condition
                ),
                // Intentional no-op, so we never attempt builder API proposals pre-merge.
                ChainHealth::PreMerge => (),
                ChainHealth::Optimistic => info!(
                    self.log(),
                    "Chain is optimistic; can't build payload";
                    "info" => "the local execution engine is syncing and the builder network \
                        cannot safely be used - unable to propose block"
                ),
                ChainHealth::Healthy => crit!(
                    self.log(),
                    "got healthy but also not healthy.. this shouldn't happen!"
                ),
            }
            return self
                .get_full_payload_caching(
                    parent_hash,
                    payload_attributes,
                    forkchoice_update_params,
                    current_fork,
                )
                .await
                .and_then(GetPayloadResponseType::try_into)
                .map(ProvenancedPayload::Local);
        }

        let (relay_result, local_result) = self
            .fetch_builder_and_local_payloads(
                builder.as_ref(),
                parent_hash,
                &builder_params,
                payload_attributes,
                forkchoice_update_params,
                current_fork,
            )
            .await;

        match (relay_result, local_result) {
            (Err(e), Ok(local)) => {
                warn!(
                    self.log(),
                    "Builder error when requesting payload";
                    "info" => "falling back to local execution client",
                    "relay_error" => ?e,
                    "local_block_hash" => ?local.block_hash(),
                    "parent_hash" => ?parent_hash,
                );
                Ok(ProvenancedPayload::Local(BlockProposalContentsType::Full(
                    local.try_into()?,
                )))
            }
            (Ok(None), Ok(local)) => {
                info!(
                    self.log(),
                    "Builder did not return a payload";
                    "info" => "falling back to local execution client",
                    "local_block_hash" => ?local.block_hash(),
                    "parent_hash" => ?parent_hash,
                );
                Ok(ProvenancedPayload::Local(BlockProposalContentsType::Full(
                    local.try_into()?,
                )))
            }
            (Err(relay_error), Err(local_error)) => {
                crit!(
                    self.log(),
                    "Unable to produce execution payload";
                    "info" => "the local EL and builder both failed - unable to propose block",
                    "relay_error" => ?relay_error,
                    "local_error" => ?local_error,
                    "parent_hash" => ?parent_hash,
                );

                Err(Error::CannotProduceHeader)
            }
            (Ok(None), Err(local_error)) => {
                crit!(
                    self.log(),
                    "Unable to produce execution payload";
                    "info" => "the local EL failed and the builder returned nothing - \
                        the block proposal will be missed",
                    "local_error" => ?local_error,
                    "parent_hash" => ?parent_hash,
                );

                Err(Error::CannotProduceHeader)
            }
            (Ok(Some(relay)), Ok(local)) => {
                let header = &relay.data.message.header();

                info!(
                    self.log(),
                    "Received local and builder payloads";
                    "relay_block_hash" => ?header.block_hash(),
                    "local_block_hash" => ?local.block_hash(),
                    "parent_hash" => ?parent_hash,
                );

                // check relay payload validity
                if let Err(reason) = verify_builder_bid(
                    &relay,
                    parent_hash,
                    payload_attributes,
                    Some(local.block_number()),
                    current_fork,
                    spec,
                ) {
                    // relay payload invalid -> return local
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_GET_PAYLOAD_BUILDER_REJECTIONS,
                        &[reason.as_ref().as_ref()],
                    );
                    warn!(
                        self.log(),
                        "Builder returned invalid payload";
                        "info" => "using local payload",
                        "reason" => %reason,
                        "relay_block_hash" => ?header.block_hash(),
                        "parent_hash" => ?parent_hash,
                    );
                    return Ok(ProvenancedPayload::Local(BlockProposalContentsType::Full(
                        local.try_into()?,
                    )));
                }

                let relay_value = *relay.data.message.value();

                let boosted_relay_value = match builder_boost_factor {
                    Some(builder_boost_factor) => {
                        (relay_value / 100).saturating_mul(builder_boost_factor.into())
                    }
                    None => relay_value,
                };

                let local_value = *local.block_value();

                if local_value >= boosted_relay_value {
                    info!(
                        self.log(),
                        "Local block is more profitable than relay block";
                        "local_block_value" => %local_value,
                        "relay_value" => %relay_value,
                        "boosted_relay_value" => %boosted_relay_value,
                        "builder_boost_factor" => ?builder_boost_factor,
                    );
                    return Ok(ProvenancedPayload::Local(BlockProposalContentsType::Full(
                        local.try_into()?,
                    )));
                }

                if local.should_override_builder().unwrap_or(false) {
                    info!(
                        self.log(),
                        "Using local payload because execution engine suggested we ignore builder payload";
                        "local_block_value" => %local_value,
                        "relay_value" => %relay_value
                    );
                    return Ok(ProvenancedPayload::Local(BlockProposalContentsType::Full(
                        local.try_into()?,
                    )));
                }

                info!(
                    self.log(),
                    "Relay block is more profitable than local block";
                    "local_block_value" => %local_value,
                    "relay_value" => %relay_value,
                    "boosted_relay_value" => %boosted_relay_value,
                    "builder_boost_factor" => ?builder_boost_factor
                );

                Ok(ProvenancedPayload::try_from(relay.data.message)?)
            }
            (Ok(Some(relay)), Err(local_error)) => {
                let header = &relay.data.message.header();

                info!(
                    self.log(),
                    "Received builder payload with local error";
                    "relay_block_hash" => ?header.block_hash(),
                    "local_error" => ?local_error,
                    "parent_hash" => ?parent_hash,
                );

                match verify_builder_bid(
                    &relay,
                    parent_hash,
                    payload_attributes,
                    None,
                    current_fork,
                    spec,
                ) {
                    Ok(()) => Ok(ProvenancedPayload::try_from(relay.data.message)?),
                    Err(reason) => {
                        metrics::inc_counter_vec(
                            &metrics::EXECUTION_LAYER_GET_PAYLOAD_BUILDER_REJECTIONS,
                            &[reason.as_ref().as_ref()],
                        );
                        crit!(
                            self.log(),
                            "Builder returned invalid payload";
                            "info" => "no local payload either - unable to propose block",
                            "reason" => %reason,
                            "relay_block_hash" => ?header.block_hash(),
                            "parent_hash" => ?parent_hash,
                        );
                        Err(Error::CannotProduceHeader)
                    }
                }
            }
        }
    }

    /// Get a full payload and cache its result in the execution layer's payload cache.
    async fn get_full_payload_caching(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
    ) -> Result<GetPayloadResponseType<T>, Error> {
        self.get_full_payload_with(
            parent_hash,
            payload_attributes,
            forkchoice_update_params,
            current_fork,
            Self::cache_payload,
        )
        .await
    }

    async fn get_full_payload_with(
        &self,
        parent_hash: ExecutionBlockHash,
        payload_attributes: &PayloadAttributes,
        forkchoice_update_params: ForkchoiceUpdateParameters,
        current_fork: ForkName,
        cache_fn: fn(
            &ExecutionLayer<T>,
            PayloadContentsRefTuple<T>,
        ) -> Option<FullPayloadContents<T>>,
    ) -> Result<GetPayloadResponseType<T>, Error> {
        self.engine()
            .request(move |engine| async move {
                let payload_id = if let Some(id) = engine
                    .get_payload_id(&parent_hash, payload_attributes)
                    .await
                {
                    // The payload id has been cached for this engine.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::HIT],
                    );
                    id
                } else {
                    // The payload id has *not* been cached. Trigger an artificial
                    // fork choice update to retrieve a payload ID.
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_PRE_PREPARED_PAYLOAD_ID,
                        &[metrics::MISS],
                    );
                    let fork_choice_state = ForkchoiceState {
                        head_block_hash: parent_hash,
                        safe_block_hash: forkchoice_update_params
                            .justified_hash
                            .unwrap_or_else(ExecutionBlockHash::zero),
                        finalized_block_hash: forkchoice_update_params
                            .finalized_hash
                            .unwrap_or_else(ExecutionBlockHash::zero),
                    };

                    let response = engine
                        .notify_forkchoice_updated(
                            fork_choice_state,
                            Some(payload_attributes.clone()),
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
                                          This has the potential to cause a missed block proposal.",
                                "status" => ?response.payload_status
                            );
                            return Err(ApiError::PayloadIdUnavailable);
                        }
                    }
                };

                let payload_response = async {
                    debug!(
                        self.log(),
                        "Issuing engine_getPayload";
                        "suggested_fee_recipient" => ?payload_attributes.suggested_fee_recipient(),
                        "prev_randao" => ?payload_attributes.prev_randao(),
                        "timestamp" => payload_attributes.timestamp(),
                        "parent_hash" => ?parent_hash,
                    );
                    let _timer = metrics::start_timer_vec(
                        &metrics::EXECUTION_LAYER_REQUEST_TIMES,
                        &[metrics::GET_PAYLOAD],
                    );
                    engine.api.get_payload::<T>(current_fork, payload_id).await
                }.await?;

                if payload_response.execution_payload_ref().fee_recipient() != payload_attributes.suggested_fee_recipient() {
                    error!(
                        self.log(),
                        "Inconsistent fee recipient";
                        "msg" => "The fee recipient returned from the Execution Engine differs \
                        from the suggested_fee_recipient set on the beacon node. This could \
                        indicate that fees are being diverted to another address. Please \
                        ensure that the value of suggested_fee_recipient is set correctly and \
                        that the Execution Engine is trusted.",
                        "fee_recipient" => ?payload_response.execution_payload_ref().fee_recipient(),
                        "suggested_fee_recipient" => ?payload_attributes.suggested_fee_recipient(),
                    );
                }
                if cache_fn(self, (payload_response.execution_payload_ref(), payload_response.blobs_bundle().ok())).is_some() {
                    warn!(
                        self.log(),
                        "Duplicate payload cached, this might indicate redundant proposal \
                             attempts."
                    );
                }

                Ok(GetPayloadResponseType::Full(payload_response))
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Maps to the `engine_newPayload` JSON-RPC call.
    pub async fn notify_new_payload(
        &self,
        new_payload_request: NewPayloadRequest<'_, T>,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::NEW_PAYLOAD],
        );

        let block_hash = new_payload_request.block_hash();
        trace!(
            self.log(),
            "Issuing engine_newPayload";
            "parent_hash" => ?new_payload_request.parent_hash(),
            "block_hash" => ?block_hash,
            "block_number" => ?new_payload_request.block_number(),
        );

        let result = self
            .engine()
            .request(|engine| engine.api.new_payload(new_payload_request))
            .await;

        if let Ok(status) = &result {
            metrics::inc_counter_vec(
                &metrics::EXECUTION_LAYER_PAYLOAD_STATUS,
                &["new_payload", status.status.into()],
            );
        }
        *self.inner.last_new_payload_errored.write().await = result.is_err();

        process_payload_status(block_hash, result, self.log())
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Update engine sync status.
    pub async fn upcheck(&self) {
        self.engine().upcheck().await;
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
    pub async fn notify_forkchoice_updated(
        &self,
        head_block_hash: ExecutionBlockHash,
        justified_block_hash: ExecutionBlockHash,
        finalized_block_hash: ExecutionBlockHash,
        current_slot: Slot,
        head_block_root: Hash256,
    ) -> Result<PayloadStatus, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::FORKCHOICE_UPDATED],
        );

        debug!(
            self.log(),
            "Issuing engine_forkchoiceUpdated";
            "finalized_block_hash" => ?finalized_block_hash,
            "justified_block_hash" => ?justified_block_hash,
            "head_block_hash" => ?head_block_hash,
            "head_block_root" => ?head_block_root,
            "current_slot" => current_slot,
        );

        let next_slot = current_slot + 1;
        let payload_attributes = self.payload_attributes(next_slot, head_block_root).await;

        // Compute the "lookahead", the time between when the payload will be produced and now.
        if let Some(ref payload_attributes) = payload_attributes {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                let timestamp = Duration::from_secs(payload_attributes.timestamp());
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

        let forkchoice_state = ForkchoiceState {
            head_block_hash,
            safe_block_hash: justified_block_hash,
            finalized_block_hash,
        };

        self.engine()
            .set_latest_forkchoice_state(forkchoice_state)
            .await;

        let result = self
            .engine()
            .request(|engine| async move {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes, self.log())
                    .await
            })
            .await;

        if let Ok(status) = &result {
            metrics::inc_counter_vec(
                &metrics::EXECUTION_LAYER_PAYLOAD_STATUS,
                &["forkchoice_updated", status.payload_status.status.into()],
            );
        }

        process_payload_status(
            head_block_hash,
            result.map(|response| response.payload_status),
            self.log(),
        )
        .map_err(Box::new)
        .map_err(Error::EngineError)
    }

    /// Returns the execution engine capabilities resulting from a call to
    /// engine_exchangeCapabilities. If the capabilities cache is not populated,
    /// or if it is populated with a cached result of age >= `age_limit`, this
    /// method will fetch the result from the execution engine and populate the
    /// cache before returning it. Otherwise it will return a cached result from
    /// a previous call.
    ///
    /// Set `age_limit` to `None` to always return the cached result
    /// Set `age_limit` to `Some(Duration::ZERO)` to force fetching from EE
    pub async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, Error> {
        self.engine()
            .request(|engine| engine.get_engine_capabilities(age_limit))
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
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
        timestamp: u64,
    ) -> Result<Option<ExecutionBlockHash>, Error> {
        let _timer = metrics::start_timer_vec(
            &metrics::EXECUTION_LAYER_REQUEST_TIMES,
            &[metrics::GET_TERMINAL_POW_BLOCK_HASH],
        );

        let hash_opt = self
            .engine()
            .request(|engine| async move {
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

                let block = self.get_pow_block_at_total_difficulty(engine, spec).await?;
                if let Some(pow_block) = block {
                    // If `terminal_block.timestamp == transition_block.timestamp`,
                    // we violate the invariant that a block's timestamp must be
                    // strictly greater than its parent's timestamp.
                    // The execution layer will reject a fcu call with such payload
                    // attributes leading to a missed block.
                    // Hence, we return `None` in such a case.
                    if pow_block.timestamp >= timestamp {
                        return Ok(None);
                    }
                }
                Ok(block.map(|b| b.block_hash))
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
    async fn get_pow_block_at_total_difficulty(
        &self,
        engine: &Engine,
        spec: &ChainSpec,
    ) -> Result<Option<ExecutionBlock>, ApiError> {
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
                    return Ok(Some(block));
                }
                let parent = self
                    .get_pow_block(engine, block.parent_hash)
                    .await?
                    .ok_or(ApiError::ExecutionBlockNotFound(block.parent_hash))?;
                let parent_reached_ttd = parent.total_difficulty >= spec.terminal_total_difficulty;

                if block_reached_ttd && !parent_reached_ttd {
                    return Ok(Some(block));
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
    /// - `None` if the `block_hash` or its parent were not present on the execution engine.
    /// - `Err(_)` if there was an error connecting to the execution engine.
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

        self.engine()
            .request(|engine| async move {
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
    async fn get_pow_block(
        &self,
        engine: &Engine,
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

    pub async fn get_payload_bodies_by_hash(
        &self,
        hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<T>>>, Error> {
        self.engine()
            .request(|engine: &Engine| async move {
                engine.api.get_payload_bodies_by_hash_v1(hashes).await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    pub async fn get_payload_bodies_by_range(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<T>>>, Error> {
        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_GET_PAYLOAD_BODIES_BY_RANGE);
        self.engine()
            .request(|engine: &Engine| async move {
                engine
                    .api
                    .get_payload_bodies_by_range_v1(start, count)
                    .await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    /// Fetch a full payload from the execution node.
    ///
    /// This will fail if the payload is not from the finalized portion of the chain.
    pub async fn get_payload_for_header(
        &self,
        header: &ExecutionPayloadHeader<T>,
        fork: ForkName,
    ) -> Result<Option<ExecutionPayload<T>>, Error> {
        let hash = header.block_hash();
        let block_number = header.block_number();

        // Handle default payload body.
        if header.block_hash() == ExecutionBlockHash::zero() {
            let payload = match fork {
                ForkName::Merge => ExecutionPayloadMerge::default().into(),
                ForkName::Capella => ExecutionPayloadCapella::default().into(),
                ForkName::Deneb => ExecutionPayloadDeneb::default().into(),
                ForkName::Base | ForkName::Altair => {
                    return Err(Error::InvalidForkForPayload);
                }
            };
            return Ok(Some(payload));
        }

        // Use efficient payload bodies by range method if supported.
        let capabilities = self.get_engine_capabilities(None).await?;
        if capabilities.get_payload_bodies_by_range_v1 {
            let mut payload_bodies = self.get_payload_bodies_by_range(block_number, 1).await?;

            if payload_bodies.len() != 1 {
                return Ok(None);
            }

            let opt_payload_body = payload_bodies.pop().flatten();
            opt_payload_body
                .map(|body| {
                    body.to_payload(header.clone())
                        .map_err(Error::InvalidPayloadBody)
                })
                .transpose()
        } else {
            // Fall back to eth_blockByHash.
            self.get_payload_by_hash_legacy(hash, fork).await
        }
    }

    pub async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, Error> {
        self.engine()
            .request(|engine| async move { engine.api.get_block_by_number(query).await })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    pub async fn get_payload_by_hash_legacy(
        &self,
        hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionPayload<T>>, Error> {
        self.engine()
            .request(|engine| async move {
                self.get_payload_by_hash_from_engine(engine, hash, fork)
                    .await
            })
            .await
            .map_err(Box::new)
            .map_err(Error::EngineError)
    }

    async fn get_payload_by_hash_from_engine(
        &self,
        engine: &Engine,
        hash: ExecutionBlockHash,
        fork: ForkName,
    ) -> Result<Option<ExecutionPayload<T>>, ApiError> {
        let _timer = metrics::start_timer(&metrics::EXECUTION_LAYER_GET_PAYLOAD_BY_BLOCK_HASH);

        if hash == ExecutionBlockHash::zero() {
            return match fork {
                ForkName::Merge => Ok(Some(ExecutionPayloadMerge::default().into())),
                ForkName::Capella => Ok(Some(ExecutionPayloadCapella::default().into())),
                ForkName::Deneb => Ok(Some(ExecutionPayloadDeneb::default().into())),
                ForkName::Base | ForkName::Altair => Err(ApiError::UnsupportedForkVariant(
                    format!("called get_payload_by_hash_from_engine with {}", fork),
                )),
            };
        }

        let Some(block) = engine
            .api
            .get_block_by_hash_with_txns::<T>(hash, fork)
            .await?
        else {
            return Ok(None);
        };

        let convert_transactions = |transactions: Vec<EthersTransaction>| {
            VariableList::new(
                transactions
                    .into_iter()
                    .map(|tx| VariableList::new(tx.rlp().to_vec()))
                    .collect::<Result<Vec<_>, ssz_types::Error>>()?,
            )
            .map_err(ApiError::SszError)
        };

        let payload = match block {
            ExecutionBlockWithTransactions::Merge(merge_block) => {
                ExecutionPayload::Merge(ExecutionPayloadMerge {
                    parent_hash: merge_block.parent_hash,
                    fee_recipient: merge_block.fee_recipient,
                    state_root: merge_block.state_root,
                    receipts_root: merge_block.receipts_root,
                    logs_bloom: merge_block.logs_bloom,
                    prev_randao: merge_block.prev_randao,
                    block_number: merge_block.block_number,
                    gas_limit: merge_block.gas_limit,
                    gas_used: merge_block.gas_used,
                    timestamp: merge_block.timestamp,
                    extra_data: merge_block.extra_data,
                    base_fee_per_gas: merge_block.base_fee_per_gas,
                    block_hash: merge_block.block_hash,
                    transactions: convert_transactions(merge_block.transactions)?,
                })
            }
            ExecutionBlockWithTransactions::Capella(capella_block) => {
                let withdrawals = VariableList::new(
                    capella_block
                        .withdrawals
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )
                .map_err(ApiError::DeserializeWithdrawals)?;
                ExecutionPayload::Capella(ExecutionPayloadCapella {
                    parent_hash: capella_block.parent_hash,
                    fee_recipient: capella_block.fee_recipient,
                    state_root: capella_block.state_root,
                    receipts_root: capella_block.receipts_root,
                    logs_bloom: capella_block.logs_bloom,
                    prev_randao: capella_block.prev_randao,
                    block_number: capella_block.block_number,
                    gas_limit: capella_block.gas_limit,
                    gas_used: capella_block.gas_used,
                    timestamp: capella_block.timestamp,
                    extra_data: capella_block.extra_data,
                    base_fee_per_gas: capella_block.base_fee_per_gas,
                    block_hash: capella_block.block_hash,
                    transactions: convert_transactions(capella_block.transactions)?,
                    withdrawals,
                })
            }
            ExecutionBlockWithTransactions::Deneb(deneb_block) => {
                let withdrawals = VariableList::new(
                    deneb_block
                        .withdrawals
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )
                .map_err(ApiError::DeserializeWithdrawals)?;
                ExecutionPayload::Deneb(ExecutionPayloadDeneb {
                    parent_hash: deneb_block.parent_hash,
                    fee_recipient: deneb_block.fee_recipient,
                    state_root: deneb_block.state_root,
                    receipts_root: deneb_block.receipts_root,
                    logs_bloom: deneb_block.logs_bloom,
                    prev_randao: deneb_block.prev_randao,
                    block_number: deneb_block.block_number,
                    gas_limit: deneb_block.gas_limit,
                    gas_used: deneb_block.gas_used,
                    timestamp: deneb_block.timestamp,
                    extra_data: deneb_block.extra_data,
                    base_fee_per_gas: deneb_block.base_fee_per_gas,
                    block_hash: deneb_block.block_hash,
                    transactions: convert_transactions(deneb_block.transactions)?,
                    withdrawals,
                    blob_gas_used: deneb_block.blob_gas_used,
                    excess_blob_gas: deneb_block.excess_blob_gas,
                })
            }
        };

        Ok(Some(payload))
    }

    pub async fn propose_blinded_beacon_block(
        &self,
        block_root: Hash256,
        block: &SignedBlindedBeaconBlock<T>,
    ) -> Result<FullPayloadContents<T>, Error> {
        debug!(
            self.log(),
            "Sending block to builder";
            "root" => ?block_root,
        );

        if let Some(builder) = self.builder() {
            let (payload_result, duration) =
                timed_future(metrics::POST_BLINDED_PAYLOAD_BUILDER, async {
                    builder
                        .post_builder_blinded_blocks(block)
                        .await
                        .map_err(Error::Builder)
                        .map(|d| d.data)
                })
                .await;

            match &payload_result {
                Ok(unblinded_response) => {
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_BUILDER_REVEAL_PAYLOAD_OUTCOME,
                        &[metrics::SUCCESS],
                    );
                    let payload = unblinded_response.payload_ref();
                    info!(
                        self.log(),
                        "Builder successfully revealed payload";
                        "relay_response_ms" => duration.as_millis(),
                        "block_root" => ?block_root,
                        "fee_recipient" => ?payload.fee_recipient(),
                        "block_hash" => ?payload.block_hash(),
                        "parent_hash" => ?payload.parent_hash()
                    )
                }
                Err(e) => {
                    metrics::inc_counter_vec(
                        &metrics::EXECUTION_LAYER_BUILDER_REVEAL_PAYLOAD_OUTCOME,
                        &[metrics::FAILURE],
                    );
                    warn!(
                        self.log(),
                        "Builder failed to reveal payload";
                        "info" => "this is common behaviour for some builders and may not indicate an issue",
                        "error" => ?e,
                        "relay_response_ms" => duration.as_millis(),
                        "block_root" => ?block_root,
                        "parent_hash" => ?block
                            .message()
                            .execution_payload()
                            .map(|payload| format!("{}", payload.parent_hash()))
                            .unwrap_or_else(|_| "unknown".to_string())
                    )
                }
            }

            payload_result
        } else {
            Err(Error::NoPayloadBuilder)
        }
    }
}

#[derive(AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum InvalidBuilderPayload {
    ParentHash {
        payload: ExecutionBlockHash,
        expected: ExecutionBlockHash,
    },
    PrevRandao {
        payload: Hash256,
        expected: Hash256,
    },
    Timestamp {
        payload: u64,
        expected: u64,
    },
    BlockNumber {
        payload: u64,
        expected: Option<u64>,
    },
    Fork {
        payload: Option<ForkName>,
        expected: ForkName,
    },
    Signature {
        signature: Signature,
        pubkey: PublicKeyBytes,
    },
    WithdrawalsRoot {
        payload: Option<Hash256>,
        expected: Option<Hash256>,
    },
}

impl fmt::Display for InvalidBuilderPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidBuilderPayload::ParentHash { payload, expected } => {
                write!(f, "payload block hash was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::PrevRandao { payload, expected } => {
                write!(f, "payload prev randao was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::Timestamp { payload, expected } => {
                write!(f, "payload timestamp was {} not {}", payload, expected)
            }
            InvalidBuilderPayload::BlockNumber { payload, expected } => {
                write!(f, "payload block number was {} not {:?}", payload, expected)
            }
            InvalidBuilderPayload::Fork { payload, expected } => {
                write!(f, "payload fork was {:?} not {}", payload, expected)
            }
            InvalidBuilderPayload::Signature { signature, pubkey } => write!(
                f,
                "invalid payload signature {} for pubkey {}",
                signature, pubkey
            ),
            InvalidBuilderPayload::WithdrawalsRoot { payload, expected } => {
                let opt_string = |opt_hash: &Option<Hash256>| {
                    opt_hash
                        .map(|hash| hash.to_string())
                        .unwrap_or_else(|| "None".to_string())
                };
                write!(
                    f,
                    "payload withdrawals root was {} not {}",
                    opt_string(payload),
                    opt_string(expected)
                )
            }
        }
    }
}

/// Perform some cursory, non-exhaustive validation of the bid returned from the builder.
fn verify_builder_bid<T: EthSpec>(
    bid: &ForkVersionedResponse<SignedBuilderBid<T>>,
    parent_hash: ExecutionBlockHash,
    payload_attributes: &PayloadAttributes,
    block_number: Option<u64>,
    current_fork: ForkName,
    spec: &ChainSpec,
) -> Result<(), Box<InvalidBuilderPayload>> {
    let is_signature_valid = bid.data.verify_signature(spec);
    let header = &bid.data.message.header();

    // Avoid logging values that we can't represent with our Prometheus library.
    let payload_value_gwei = bid.data.message.value() / 1_000_000_000;
    if payload_value_gwei <= Uint256::from(i64::max_value()) {
        metrics::set_gauge_vec(
            &metrics::EXECUTION_LAYER_PAYLOAD_BIDS,
            &[metrics::BUILDER],
            payload_value_gwei.low_u64() as i64,
        );
    }

    let expected_withdrawals_root = payload_attributes
        .withdrawals()
        .ok()
        .cloned()
        .map(|withdrawals| Withdrawals::<T>::from(withdrawals).tree_hash_root());
    let payload_withdrawals_root = header.withdrawals_root().ok().copied();

    if header.parent_hash() != parent_hash {
        Err(Box::new(InvalidBuilderPayload::ParentHash {
            payload: header.parent_hash(),
            expected: parent_hash,
        }))
    } else if header.prev_randao() != payload_attributes.prev_randao() {
        Err(Box::new(InvalidBuilderPayload::PrevRandao {
            payload: header.prev_randao(),
            expected: payload_attributes.prev_randao(),
        }))
    } else if header.timestamp() != payload_attributes.timestamp() {
        Err(Box::new(InvalidBuilderPayload::Timestamp {
            payload: header.timestamp(),
            expected: payload_attributes.timestamp(),
        }))
    } else if block_number.map_or(false, |n| n != header.block_number()) {
        Err(Box::new(InvalidBuilderPayload::BlockNumber {
            payload: header.block_number(),
            expected: block_number,
        }))
    } else if bid.version != Some(current_fork) {
        Err(Box::new(InvalidBuilderPayload::Fork {
            payload: bid.version,
            expected: current_fork,
        }))
    } else if !is_signature_valid {
        Err(Box::new(InvalidBuilderPayload::Signature {
            signature: bid.data.signature.clone(),
            pubkey: *bid.data.message.pubkey(),
        }))
    } else if payload_withdrawals_root != expected_withdrawals_root {
        Err(Box::new(InvalidBuilderPayload::WithdrawalsRoot {
            payload: payload_withdrawals_root,
            expected: expected_withdrawals_root,
        }))
    } else {
        Ok(())
    }
}

/// A helper function to record the time it takes to execute a future.
async fn timed_future<F: Future<Output = T>, T>(metric: &str, future: F) -> (T, Duration) {
    let start = Instant::now();
    let result = future.await;
    let duration = start.elapsed();
    metrics::observe_timer_vec(&metrics::EXECUTION_LAYER_REQUEST_TIMES, &[metric], duration);
    (result, duration)
}

#[cfg(test)]
/// Returns the duration since the unix epoch.
fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn noop<T: EthSpec>(
    _: &ExecutionLayer<T>,
    _: PayloadContentsRefTuple<T>,
) -> Option<FullPayloadContents<T>> {
    None
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
    async fn test_forked_terminal_block() {
        let runtime = TestRuntime::default();
        let (mock, block_hash) = MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_terminal_block()
            .produce_forked_pow_block();
        assert!(mock
            .el
            .is_valid_terminal_pow_block_hash(block_hash, &mock.spec)
            .await
            .unwrap()
            .unwrap());
    }

    #[tokio::test]
    async fn finds_valid_terminal_block_hash() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engine().upcheck().await;
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    None
                )
            })
            .await
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    Some(terminal_block.unwrap().block_hash)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_terminal_block_with_equal_timestamp() {
        let runtime = TestRuntime::default();
        MockExecutionLayer::default_params(runtime.task_executor.clone())
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
                el.engine().upcheck().await;
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp_now())
                        .await
                        .unwrap(),
                    None
                )
            })
            .await
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
                let timestamp = terminal_block.as_ref().map(|b| b.timestamp).unwrap();
                assert_eq!(
                    el.get_terminal_pow_block_hash(&spec, timestamp)
                        .await
                        .unwrap(),
                    None
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
                el.engine().upcheck().await;
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
                el.engine().upcheck().await;
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
                el.engine().upcheck().await;
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
