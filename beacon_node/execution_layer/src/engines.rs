//! Provides generic behaviour for multiple execution engines, specifically fallback behaviour.

use crate::engine_api::{
    EngineApi, Error as EngineApiError, ForkchoiceUpdatedResponse, PayloadAttributes, PayloadId,
};
use futures::future::join_all;
use lru::LruCache;
use slog::{crit, debug, info, warn, Logger};
use std::future::Future;
use tokio::sync::{Mutex, RwLock};
use types::{Address, ExecutionBlockHash, Hash256};

/// The number of payload IDs that will be stored for each `Engine`.
///
/// Since the size of each value is small (~100 bytes) a large number is used for safety.
const PAYLOAD_ID_LRU_CACHE_SIZE: usize = 512;

/// Stores the remembered state of a engine.
#[derive(Copy, Clone, PartialEq)]
enum EngineState {
    Synced,
    Offline,
    Syncing,
    AuthFailed,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct ForkChoiceState {
    pub head_block_hash: ExecutionBlockHash,
    pub safe_block_hash: ExecutionBlockHash,
    pub finalized_block_hash: ExecutionBlockHash,
}

/// Used to enable/disable logging on some tasks.
#[derive(Copy, Clone, PartialEq)]
pub enum Logging {
    Enabled,
    Disabled,
}

impl Logging {
    pub fn is_enabled(&self) -> bool {
        match self {
            Logging::Enabled => true,
            Logging::Disabled => false,
        }
    }
}

#[derive(Hash, PartialEq, std::cmp::Eq)]
struct PayloadIdCacheKey {
    pub head_block_hash: ExecutionBlockHash,
    pub timestamp: u64,
    pub prev_randao: Hash256,
    pub suggested_fee_recipient: Address,
}

/// An execution engine.
pub struct Engine<T> {
    pub id: String,
    pub api: T,
    payload_id_cache: Mutex<LruCache<PayloadIdCacheKey, PayloadId>>,
    state: RwLock<EngineState>,
}

impl<T> Engine<T> {
    /// Creates a new, offline engine.
    pub fn new(id: String, api: T) -> Self {
        Self {
            id,
            api,
            payload_id_cache: Mutex::new(LruCache::new(PAYLOAD_ID_LRU_CACHE_SIZE)),
            state: RwLock::new(EngineState::Offline),
        }
    }

    pub async fn get_payload_id(
        &self,
        head_block_hash: ExecutionBlockHash,
        timestamp: u64,
        prev_randao: Hash256,
        suggested_fee_recipient: Address,
    ) -> Option<PayloadId> {
        self.payload_id_cache
            .lock()
            .await
            .get(&PayloadIdCacheKey {
                head_block_hash,
                timestamp,
                prev_randao,
                suggested_fee_recipient,
            })
            .cloned()
    }
}

impl<T: EngineApi> Engine<T> {
    pub async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkChoiceState,
        payload_attributes: Option<PayloadAttributes>,
        log: &Logger,
    ) -> Result<ForkchoiceUpdatedResponse, EngineApiError> {
        let response = self
            .api
            .forkchoice_updated_v1(forkchoice_state, payload_attributes)
            .await?;

        if let Some(payload_id) = response.payload_id {
            if let Some(key) =
                payload_attributes.map(|pa| PayloadIdCacheKey::new(&forkchoice_state, &pa))
            {
                self.payload_id_cache.lock().await.put(key, payload_id);
            } else {
                debug!(
                    log,
                    "Engine returned unexpected payload_id";
                    "payload_id" => ?payload_id
                );
            }
        }

        Ok(response)
    }
}

/// Holds multiple execution engines and provides functionality for managing them in a fallback
/// manner.
pub struct Engines<T> {
    pub engines: Vec<Engine<T>>,
    pub latest_forkchoice_state: RwLock<Option<ForkChoiceState>>,
    pub log: Logger,
}

#[derive(Debug)]
pub enum EngineError {
    Offline { id: String },
    Api { id: String, error: EngineApiError },
    Auth { id: String },
}

impl<T: EngineApi> Engines<T> {
    async fn get_latest_forkchoice_state(&self) -> Option<ForkChoiceState> {
        *self.latest_forkchoice_state.read().await
    }

    pub async fn set_latest_forkchoice_state(&self, state: ForkChoiceState) {
        *self.latest_forkchoice_state.write().await = Some(state);
    }

    async fn send_latest_forkchoice_state(&self, engine: &Engine<T>) {
        let latest_forkchoice_state = self.get_latest_forkchoice_state().await;

        if let Some(forkchoice_state) = latest_forkchoice_state {
            info!(
                self.log,
                "Issuing forkchoiceUpdated";
                "forkchoice_state" => ?forkchoice_state,
                "id" => &engine.id,
            );

            // For simplicity, payload attributes are never included in this call. It may be
            // reasonable to include them in the future.
            if let Err(e) = engine
                .api
                .forkchoice_updated_v1(forkchoice_state, None)
                .await
            {
                debug!(
                    self.log,
                    "Failed to issue latest head to engine";
                    "error" => ?e,
                    "id" => &engine.id,
                );
            }
        } else {
            debug!(
                self.log,
                "No head, not sending to engine";
                "id" => &engine.id,
            );
        }
    }

    /// Returns `true` if there is at least one engine with a "synced" status.
    pub async fn any_synced(&self) -> bool {
        for engine in &self.engines {
            if *engine.state.read().await == EngineState::Synced {
                return true;
            }
        }
        false
    }

    /// Run the `EngineApi::upcheck` function on all nodes which are currently offline.
    ///
    /// This can be used to try and recover any offline nodes.
    pub async fn upcheck_not_synced(&self, logging: Logging) {
        let upcheck_futures = self.engines.iter().map(|engine| async move {
            let mut state_lock = engine.state.write().await;
            if *state_lock != EngineState::Synced {
                match engine.api.upcheck().await {
                    Ok(()) => {
                        if logging.is_enabled() {
                            info!(
                                self.log,
                                "Execution engine online";
                                "id" => &engine.id
                            );
                        }

                        // Send the node our latest forkchoice_state.
                        self.send_latest_forkchoice_state(engine).await;

                        *state_lock = EngineState::Synced
                    }
                    Err(EngineApiError::IsSyncing) => {
                        if logging.is_enabled() {
                            warn!(
                                self.log,
                                "Execution engine syncing";
                                "id" => &engine.id
                            )
                        }

                        // Send the node our latest forkchoice_state, it may assist with syncing.
                        self.send_latest_forkchoice_state(engine).await;

                        *state_lock = EngineState::Syncing
                    }
                    Err(EngineApiError::Auth(err)) => {
                        if logging.is_enabled() {
                            warn!(
                                self.log,
                                "Failed jwt authorization";
                                "error" => ?err,
                                "id" => &engine.id
                            );
                        }

                        *state_lock = EngineState::AuthFailed
                    }
                    Err(e) => {
                        if logging.is_enabled() {
                            warn!(
                                self.log,
                                "Execution engine offline";
                                "error" => ?e,
                                "id" => &engine.id
                            )
                        }
                    }
                }
            }
            *state_lock
        });

        let num_synced = join_all(upcheck_futures)
            .await
            .into_iter()
            .filter(|state: &EngineState| *state == EngineState::Synced)
            .count();

        if num_synced == 0 && logging.is_enabled() {
            crit!(
                self.log,
                "No synced execution engines";
            )
        }
    }

    /// Run `func` on all engines, in the order in which they are defined, returning the first
    /// successful result that is found.
    ///
    /// This function might try to run `func` twice. If all nodes return an error on the first time
    /// it runs, it will try to upcheck all offline nodes and then run the function again.
    pub async fn first_success<'a, F, G, H>(&'a self, func: F) -> Result<H, Vec<EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G + Copy,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        match self.first_success_without_retry(func).await {
            Ok(result) => Ok(result),
            Err(mut first_errors) => {
                // Try to recover some nodes.
                self.upcheck_not_synced(Logging::Enabled).await;
                // Retry the call on all nodes.
                match self.first_success_without_retry(func).await {
                    Ok(result) => Ok(result),
                    Err(second_errors) => {
                        first_errors.extend(second_errors);
                        Err(first_errors)
                    }
                }
            }
        }
    }

    /// Run `func` on all engines, in the order in which they are defined, returning the first
    /// successful result that is found.
    async fn first_success_without_retry<'a, F, G, H>(
        &'a self,
        func: F,
    ) -> Result<H, Vec<EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let mut errors = vec![];

        for engine in &self.engines {
            let (engine_synced, engine_auth_failed) = {
                let state = engine.state.read().await;
                (
                    *state == EngineState::Synced,
                    *state == EngineState::AuthFailed,
                )
            };
            if engine_synced {
                match func(engine).await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        debug!(
                            self.log,
                            "Execution engine call failed";
                            "error" => ?error,
                            "id" => &engine.id
                        );
                        *engine.state.write().await = EngineState::Offline;
                        errors.push(EngineError::Api {
                            id: engine.id.clone(),
                            error,
                        })
                    }
                }
            } else if engine_auth_failed {
                errors.push(EngineError::Auth {
                    id: engine.id.clone(),
                })
            } else {
                errors.push(EngineError::Offline {
                    id: engine.id.clone(),
                })
            }
        }

        Err(errors)
    }

    /// Runs `func` on all nodes concurrently, returning all results. Any nodes that are offline
    /// will be ignored, however all synced or unsynced nodes will receive the broadcast.
    ///
    /// This function might try to run `func` twice. If all nodes return an error on the first time
    /// it runs, it will try to upcheck all offline nodes and then run the function again.
    pub async fn broadcast<'a, F, G, H>(&'a self, func: F) -> Vec<Result<H, EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G + Copy,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let first_results = self.broadcast_without_retry(func).await;

        let mut any_offline = false;
        for result in &first_results {
            match result {
                Ok(_) => return first_results,
                Err(EngineError::Offline { .. }) => any_offline = true,
                _ => (),
            }
        }

        if any_offline {
            self.upcheck_not_synced(Logging::Enabled).await;
            self.broadcast_without_retry(func).await
        } else {
            first_results
        }
    }

    /// Runs `func` on all nodes concurrently, returning all results.
    pub async fn broadcast_without_retry<'a, F, G, H>(
        &'a self,
        func: F,
    ) -> Vec<Result<H, EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let func = &func;
        let futures = self.engines.iter().map(|engine| async move {
            let is_offline = *engine.state.read().await == EngineState::Offline;
            if !is_offline {
                func(engine).await.map_err(|error| {
                    debug!(
                        self.log,
                        "Execution engine call failed";
                        "error" => ?error,
                        "id" => &engine.id
                    );
                    EngineError::Api {
                        id: engine.id.clone(),
                        error,
                    }
                })
            } else {
                Err(EngineError::Offline {
                    id: engine.id.clone(),
                })
            }
        });

        join_all(futures).await
    }
}

impl PayloadIdCacheKey {
    fn new(state: &ForkChoiceState, attributes: &PayloadAttributes) -> Self {
        Self {
            head_block_hash: state.head_block_hash,
            timestamp: attributes.timestamp,
            prev_randao: attributes.prev_randao,
            suggested_fee_recipient: attributes.suggested_fee_recipient,
        }
    }
}
