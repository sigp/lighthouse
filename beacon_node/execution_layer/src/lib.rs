//! This crate provides an abstraction over one or more *execution engines*. An execution engine
//! was formerly known as an "eth1 node", like Geth, Nethermind, Erigon, etc.
//!
//! This crate only provides useful functionality for "The Merge", it does not provide any of the
//! deposit-contract functionality that the `beacon_node/eth1` crate already provides.

use auth::{Auth, JwtKey};
use engine_api::{Error as ApiError, *};
use engines::{Engine, EngineError, Engines, ForkChoiceState, Logging};
use lru::LruCache;
use payload_status::process_multiple_payload_statuses;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, info, trace, Logger};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::{
    sync::{Mutex, MutexGuard},
    time::{sleep, sleep_until, Instant},
};
use types::{ChainSpec, Epoch, ExecutionBlockHash, ProposerPreparationData};

pub use engine_api::{http::HttpJsonRpc, PayloadAttributes, PayloadStatusV1Status};
pub use payload_status::PayloadStatus;

mod engine_api;
mod engines;
mod payload_status;
pub mod test_utils;

/// Name for the default file used for the jwt secret.
pub const DEFAULT_JWT_FILE: &str = "jwtsecret";

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

#[derive(Debug)]
pub enum Error {
    NoEngines,
    ApiError(ApiError),
    EngineErrors(Vec<EngineError>),
    NotSynced,
    ShuttingDown,
    FeeRecipientUnspecified,
    ConsensusFailure,
    MissingLatestValidHash,
    InvalidJWTSecret(String),
    NoAuthProvided(String),
    MissingLatestValidHash,
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

#[derive(Clone)]
pub struct ProposerPreparationDataEntry {
    update_epoch: Epoch,
    preparation_data: ProposerPreparationData,
}

struct Inner {
    engines: Engines<HttpJsonRpc>,
    suggested_fee_recipient: Option<Address>,
    proposer_preparation_data: Mutex<HashMap<u64, ProposerPreparationDataEntry>>,
    execution_blocks: Mutex<LruCache<ExecutionBlockHash, ExecutionBlock>>,
    executor: TaskExecutor,
    log: Logger,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint urls for EL nodes that are running the engine api.
    pub execution_endpoints: Vec<SensitiveUrl>,
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

fn strip_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
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
pub struct ExecutionLayer {
    inner: Arc<Inner>,
}

impl ExecutionLayer {
    /// Instantiate `Self` with Execution engines specified using `Config`, all using the JSON-RPC via HTTP.
    pub fn from_config(config: Config, executor: TaskExecutor, log: Logger) -> Result<Self, Error> {
        let Config {
            execution_endpoints: urls,
            mut secret_files,
            suggested_fee_recipient,
            jwt_id,
            jwt_version,
            default_datadir,
        } = config;

        if urls.is_empty() {
            return Err(Error::NoEngines);
        }

        // Extend the jwt secret files with the default jwt secret path if not provided via cli.
        // This ensures that we have a jwt secret for every EL.
        secret_files.extend(vec![
            default_datadir.join(DEFAULT_JWT_FILE);
            urls.len().saturating_sub(secret_files.len())
        ]);

        let secrets: Vec<(JwtKey, PathBuf)> = secret_files
            .iter()
            .map(|p| {
                // Read secret from file if it already exists
                if p.exists() {
                    std::fs::read_to_string(p)
                        .map_err(|e| {
                            format!("Failed to read JWT secret file {:?}, error: {:?}", p, e)
                        })
                        .and_then(|ref s| {
                            let secret = JwtKey::from_slice(
                                &hex::decode(strip_prefix(s))
                                    .map_err(|e| format!("Invalid hex string: {:?}", e))?,
                            )?;
                            Ok((secret, p.to_path_buf()))
                        })
                } else {
                    // Create a new file and write a randomly generated secret to it if file does not exist
                    std::fs::File::options()
                        .write(true)
                        .create_new(true)
                        .open(p)
                        .map_err(|e| {
                            format!("Failed to open JWT secret file {:?}, error: {:?}", p, e)
                        })
                        .and_then(|mut f| {
                            let secret = auth::JwtKey::random();
                            f.write_all(secret.to_string().as_bytes()).map_err(|e| {
                                format!("Failed to write to JWT secret file: {:?}", e)
                            })?;
                            Ok((secret, p.to_path_buf()))
                        })
                }
            })
            .collect::<Result<_, _>>()
            .map_err(Error::InvalidJWTSecret)?;

        let engines: Vec<Engine<_>> = urls
            .into_iter()
            .zip(secrets.into_iter())
            .map(|(url, (secret, path))| {
                let id = url.to_string();
                let auth = Auth::new(secret, jwt_id.clone(), jwt_version.clone());
                debug!(log, "Loaded execution endpoint"; "endpoint" => %id, "jwt_path" => ?path);
                let api = HttpJsonRpc::new_with_auth(url, auth)?;
                Ok(Engine::new(id, api))
            })
            .collect::<Result<_, ApiError>>()?;

        let inner = Inner {
            engines: Engines {
                engines,
                latest_forkchoice_state: <_>::default(),
                log: log.clone(),
            },
            suggested_fee_recipient,
            proposer_preparation_data: Mutex::new(HashMap::new()),
            execution_blocks: Mutex::new(LruCache::new(EXECUTION_BLOCKS_LRU_CACHE_SIZE)),
            executor,
            log,
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl ExecutionLayer {
    fn engines(&self) -> &Engines<HttpJsonRpc> {
        &self.inner.engines
    }

    fn executor(&self) -> &TaskExecutor {
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

    fn log(&self) -> &Logger {
        &self.inner.log
    }

    /// Convenience function to allow calling async functions in a non-async context.
    pub fn block_on<'a, T, U, V>(&'a self, generate_future: T) -> Result<V, Error>
    where
        T: Fn(&'a Self) -> U,
        U: Future<Output = Result<V, Error>>,
    {
        let runtime = self
            .executor()
            .runtime()
            .upgrade()
            .ok_or(Error::ShuttingDown)?;
        // TODO(merge): respect the shutdown signal.
        runtime.block_on(generate_future(self))
    }

    /// Convenience function to allow calling async functions in a non-async context.
    ///
    /// The function is "generic" since it does not enforce a particular return type on
    /// `generate_future`.
    pub fn block_on_generic<'a, T, U, V>(&'a self, generate_future: T) -> Result<V, Error>
    where
        T: Fn(&'a Self) -> U,
        U: Future<Output = V>,
    {
        let runtime = self
            .executor()
            .runtime()
            .upgrade()
            .ok_or(Error::ShuttingDown)?;
        // TODO(merge): respect the shutdown signal.
        Ok(runtime.block_on(generate_future(self)))
    }

    /// Convenience function to allow spawning a task without waiting for the result.
    pub fn spawn<T, U>(&self, generate_future: T, name: &'static str)
    where
        T: FnOnce(Self) -> U,
        U: Future<Output = ()> + Send + 'static,
    {
        self.executor().spawn(generate_future(self.clone()), name);
    }

    /// Spawns a routine which attempts to keep the execution engines online.
    pub fn spawn_watchdog_routine<S: SlotClock + 'static>(&self, slot_clock: S) {
        let watchdog = |el: ExecutionLayer| async move {
            // Run one task immediately.
            el.watchdog_task().await;

            let recurring_task =
                |el: ExecutionLayer, now: Instant, duration_to_next_slot: Duration| async move {
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

    /// Spawns a routine which cleans the cached proposer preparations periodically.
    pub fn spawn_clean_proposer_preparation_routine<S: SlotClock + 'static, T: EthSpec>(
        &self,
        slot_clock: S,
    ) {
        let preparation_cleaner = |el: ExecutionLayer| async move {
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
                            .clean_proposer_preparation(current_epoch)
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

    /// Returns `true` if there is at least one synced and reachable engine.
    pub async fn is_synced(&self) -> bool {
        self.engines().any_synced().await
    }

    /// Updates the proposer preparation data provided by validators
    pub fn update_proposer_preparation_blocking(
        &self,
        update_epoch: Epoch,
        preparation_data: &[ProposerPreparationData],
    ) -> Result<(), Error> {
        self.block_on_generic(|_| async move {
            self.update_proposer_preparation(update_epoch, preparation_data)
                .await
        })?
    }

    /// Updates the proposer preparation data provided by validators
    async fn update_proposer_preparation(
        &self,
        update_epoch: Epoch,
        preparation_data: &[ProposerPreparationData],
    ) -> Result<(), Error> {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;
        for preparation_entry in preparation_data {
            proposer_preparation_data.insert(
                preparation_entry.validator_index,
                ProposerPreparationDataEntry {
                    update_epoch,
                    preparation_data: preparation_entry.clone(),
                },
            );
        }

        Ok(())
    }

    /// Removes expired entries from cached proposer preparations
    async fn clean_proposer_preparation(&self, current_epoch: Epoch) -> Result<(), Error> {
        let mut proposer_preparation_data = self.proposer_preparation_data().await;

        // Keep all entries that have been updated in the last 2 epochs
        let retain_epoch = current_epoch.saturating_sub(Epoch::new(2));
        proposer_preparation_data.retain(|_validator_index, preparation_entry| {
            preparation_entry.update_epoch >= retain_epoch
        });

        Ok(())
    }

    /// Returns the fee-recipient address that should be used to build a block
    async fn get_suggested_fee_recipient(&self, proposer_index: u64) -> Address {
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
    pub async fn get_payload<T: EthSpec>(
        &self,
        parent_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        finalized_block_hash: ExecutionBlockHash,
        proposer_index: u64,
    ) -> Result<ExecutionPayload<T>, Error> {
        let suggested_fee_recipient = self.get_suggested_fee_recipient(proposer_index).await;

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
                    id
                } else {
                    // The payload id has *not* been cached for this engine. Trigger an artificial
                    // fork choice update to retrieve a payload ID.
                    //
                    // TODO(merge): a better algorithm might try to favour a node that already had a
                    // cached payload id, since a payload that has had more time to produce is
                    // likely to be more profitable.
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

                    engine
                        .notify_forkchoice_updated(
                            fork_choice_state,
                            Some(payload_attributes),
                            self.log(),
                        )
                        .await
                        .map(|response| response.payload_id)?
                        .ok_or_else(|| {
                            error!(
                                self.log(),
                                "Exec engine unable to produce payload";
                                "msg" => "No payload ID, the engine is likely syncing. \
                                          This has the potential to cause a missed block proposal.",
                            );

                            ApiError::PayloadIdUnavailable
                        })?
                };

                engine.api.get_payload_v1(payload_id).await
            })
            .await
            .map_err(Error::EngineErrors)
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
    pub async fn notify_new_payload<T: EthSpec>(
        &self,
        execution_payload: &ExecutionPayload<T>,
    ) -> Result<PayloadStatus, Error> {
        trace!(
            self.log(),
            "Issuing engine_newPayload";
            "parent_hash" => ?execution_payload.parent_hash,
            "block_hash" => ?execution_payload.block_hash,
            "block_number" => execution_payload.block_number,
        );

        let broadcast_results = self
            .engines()
            .broadcast(|engine| engine.api.new_payload_v1(execution_payload.clone()))
            .await;

        process_multiple_payload_statuses(
            execution_payload.block_hash,
            broadcast_results.into_iter(),
            self.log(),
        )
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
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<PayloadStatus, Error> {
        trace!(
            self.log(),
            "Issuing engine_forkchoiceUpdated";
            "finalized_block_hash" => ?finalized_block_hash,
            "head_block_hash" => ?head_block_hash,
        );

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

        let broadcast_results = self
            .engines()
            .broadcast(|engine| async move {
                engine
                    .notify_forkchoice_updated(forkchoice_state, payload_attributes, self.log())
                    .await
            })
            .await;

        process_multiple_payload_statuses(
            head_block_hash,
            broadcast_results
                .into_iter()
                .map(|result| result.map(|response| response.payload_status)),
            self.log(),
        )
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
            .map_err(Error::EngineErrors)?;

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
        engine: &Engine<HttpJsonRpc>,
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
        let broadcast_results = self
            .engines()
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
            .await;

        let mut errors = vec![];
        let mut terminal = 0;
        let mut not_terminal = 0;
        let mut block_missing = 0;
        for result in broadcast_results {
            match result {
                Ok(Some(true)) => terminal += 1,
                Ok(Some(false)) => not_terminal += 1,
                Ok(None) => block_missing += 1,
                Err(e) => errors.push(e),
            }
        }

        if terminal > 0 && not_terminal > 0 {
            crit!(
                self.log(),
                "Consensus failure between execution nodes";
                "method" => "is_valid_terminal_pow_block_hash"
            );
        }

        if terminal > 0 {
            Ok(Some(true))
        } else if not_terminal > 0 {
            Ok(Some(false))
        } else if block_missing > 0 {
            Ok(None)
        } else {
            Err(Error::EngineErrors(errors))
        }
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
        engine: &Engine<HttpJsonRpc>,
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::MockExecutionLayer as GenericMockExecutionLayer;
    use types::MainnetEthSpec;

    type MockExecutionLayer = GenericMockExecutionLayer<MainnetEthSpec>;

    #[tokio::test]
    async fn produce_three_valid_pos_execution_blocks() {
        MockExecutionLayer::default_params()
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
        MockExecutionLayer::default_params()
            .move_to_block_prior_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
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
        MockExecutionLayer::default_params()
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
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
        MockExecutionLayer::default_params()
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, terminal_block| async move {
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
        MockExecutionLayer::default_params()
            .move_to_terminal_block()
            .with_terminal_block(|spec, el, _| async move {
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
