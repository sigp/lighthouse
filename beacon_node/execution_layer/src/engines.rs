//! Provides generic behaviour for multiple execution engines, specifically fallback behaviour.

use crate::engine_api::{
    Builder, EngineApi, Error as EngineApiError, ForkchoiceUpdatedResponse, PayloadAttributes,
    PayloadId,
};
use crate::{BuilderApi, HttpJsonRpc};
use async_trait::async_trait;
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
    pub api: HttpJsonRpc<T>,
    payload_id_cache: Mutex<LruCache<PayloadIdCacheKey, PayloadId>>,
    state: RwLock<EngineState>,
}

impl<T> Engine<T> {
    /// Creates a new, offline engine.
    pub fn new(id: String, api: HttpJsonRpc<T>) -> Self {
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

#[async_trait]
impl Builder for Engine<EngineApi> {
    async fn notify_forkchoice_updated(
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

#[async_trait]
impl Builder for Engine<BuilderApi> {
    async fn notify_forkchoice_updated(
        &self,
        forkchoice_state: ForkChoiceState,
        pa: Option<PayloadAttributes>,
        log: &Logger,
    ) -> Result<ForkchoiceUpdatedResponse, EngineApiError> {
        let payload_attributes = pa.ok_or(EngineApiError::InvalidBuilderQuery)?;
        let response = self
            .api
            .forkchoice_updated_v1(forkchoice_state, Some(payload_attributes))
            .await?;

        if let Some(payload_id) = response.payload_id {
            let key = PayloadIdCacheKey::new(&forkchoice_state, &payload_attributes);
            self.payload_id_cache.lock().await.put(key, payload_id);
        } else {
            warn!(
                log,
                "Builder should have returned a payload_id for attributes {:?}", payload_attributes
            );
        }

        Ok(response)
    }
}

/// Holds multiple execution engines and provides functionality for managing them in a fallback
/// manner.
pub struct Engines {
    pub engine: Engine<EngineApi>,
    pub latest_forkchoice_state: RwLock<Option<ForkChoiceState>>,
    pub log: Logger,
}

pub struct Builders {
    pub builders: Vec<Engine<BuilderApi>>,
    pub log: Logger,
}

#[derive(Debug)]
pub enum EngineError {
    Offline { id: String },
    Api { id: String, error: EngineApiError },
    Auth { id: String },
}

impl Engines {
    async fn get_latest_forkchoice_state(&self) -> Option<ForkChoiceState> {
        *self.latest_forkchoice_state.read().await
    }

    pub async fn set_latest_forkchoice_state(&self, state: ForkChoiceState) {
        *self.latest_forkchoice_state.write().await = Some(state);
    }

    async fn send_latest_forkchoice_state(&self) {
        let latest_forkchoice_state = self.get_latest_forkchoice_state().await;

        if let Some(forkchoice_state) = latest_forkchoice_state {
            if forkchoice_state.head_block_hash == ExecutionBlockHash::zero() {
                debug!(
                    self.log,
                    "No need to call forkchoiceUpdated";
                    "msg" => "head does not have execution enabled",
                    "id" => &self.engine.id,
                );
                return;
            }

            info!(
                self.log,
                "Issuing forkchoiceUpdated";
                "forkchoice_state" => ?forkchoice_state,
                "id" => &self.engine.id,
            );

            // For simplicity, payload attributes are never included in this call. It may be
            // reasonable to include them in the future.
            if let Err(e) = self
                .engine
                .api
                .forkchoice_updated_v1(forkchoice_state, None)
                .await
            {
                debug!(
                    self.log,
                    "Failed to issue latest head to engine";
                    "error" => ?e,
                    "id" => &self.engine.id,
                );
            }
        } else {
            debug!(
                self.log,
                "No head, not sending to engine";
                "id" => &self.engine.id,
            );
        }
    }

    /// Returns `true` if the engine has a "synced" status.
    pub async fn is_synced(&self) -> bool {
        *self.engine.state.read().await == EngineState::Synced
    }
    /// Run the `EngineApi::upcheck` function if the node's last known state is not synced. This
    /// might be used to recover the node if offline.
    pub async fn upcheck_not_synced(&self, logging: Logging) {
        let mut state_lock = self.engine.state.write().await;
        if *state_lock != EngineState::Synced {
            match self.engine.api.upcheck().await {
                Ok(()) => {
                    if logging.is_enabled() {
                        info!(
                            self.log,
                            "Execution engine online";
                        );
                    }
                    // Send the node our latest forkchoice_state.
                    self.send_latest_forkchoice_state().await;

                    *state_lock = EngineState::Synced
                }
                Err(EngineApiError::IsSyncing) => {
                    if logging.is_enabled() {
                        warn!(
                            self.log,
                            "Execution engine syncing";
                        )
                    }

                    // Send the node our latest forkchoice_state, it may assist with syncing.
                    self.send_latest_forkchoice_state().await;

                    *state_lock = EngineState::Syncing
                }
                Err(EngineApiError::Auth(err)) => {
                    if logging.is_enabled() {
                        warn!(
                            self.log,
                            "Failed jwt authorization";
                            "error" => ?err,
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
                        )
                    }
                }
            }
        }

        let is_synced = *state_lock == EngineState::Synced;

        if is_synced && logging.is_enabled() {
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
        F: Fn(&'a Engine<EngineApi>) -> G + Copy,
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
    pub async fn first_success_without_retry<'a, F, G, H>(
        &'a self,
        func: F,
    ) -> Result<H, Vec<EngineError>>
    where
        F: Fn(&'a Engine<EngineApi>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let mut errors = vec![];

        let (engine_synced, engine_auth_failed) = {
            let state = self.engine.state.read().await;
            (
                *state == EngineState::Synced,
                *state == EngineState::AuthFailed,
            )
        };
        if engine_synced {
            match func(&self.engine).await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    debug!(
                        self.log,
                        "Execution engine call failed";
                        "error" => ?error,
                        "id" => &&self.engine.id
                    );
                    *self.engine.state.write().await = EngineState::Offline;
                    errors.push(EngineError::Api {
                        id: self.engine.id.clone(),
                        error,
                    })
                }
            }
        } else if engine_auth_failed {
            errors.push(EngineError::Auth {
                id: self.engine.id.clone(),
            })
        } else {
            errors.push(EngineError::Offline {
                id: self.engine.id.clone(),
            })
        }

        Err(errors)
    }

    /// Runs `func` on the node.
    ///
    /// This function might try to run `func` twice. If all nodes return an error on the first time
    /// it runs, it will try to upcheck all offline nodes and then run the function again.
    pub async fn broadcast<'a, F, G, H>(&'a self, func: F) -> Result<H, EngineError>
    where
        F: Fn(&'a Engine<EngineApi>) -> G + Copy,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        match self.broadcast_without_retry(func).await {
            Err(EngineError::Offline { .. }) => {
                self.upcheck_not_synced(Logging::Enabled).await;
                self.broadcast_without_retry(func).await
            }
            other => other,
        }
    }

    /// Runs `func` on the node if it's last state is not offline.
    pub async fn broadcast_without_retry<'a, F, G, H>(&'a self, func: F) -> Result<H, EngineError>
    where
        F: Fn(&'a Engine<EngineApi>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let func = &func;
        if *self.engine.state.read().await == EngineState::Offline {
            Err(EngineError::Offline {
                id: self.engine.id.clone(),
            })
        } else {
            match func(&self.engine).await {
                Ok(res) => Ok(res),
                Err(error) => {
                    debug!(
                        self.log,
                        "Execution engine call failed";
                        "error" => ?error,
                    );
                    *self.engine.state.write().await = EngineState::Offline;
                    Err(EngineError::Api {
                        id: self.engine.id.clone(),
                        error,
                    })
                }
            }
        }
    }
}

impl Builders {
    pub async fn first_success_without_retry<'a, F, G, H>(
        &'a self,
        func: F,
    ) -> Result<H, Vec<EngineError>>
    where
        F: Fn(&'a Engine<BuilderApi>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let mut errors = vec![];

        for builder in &self.builders {
            match func(builder).await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    debug!(
                        self.log,
                        "Builder call failed";
                        "error" => ?error,
                        "id" => &builder.id
                    );
                    errors.push(EngineError::Api {
                        id: builder.id.clone(),
                        error,
                    })
                }
            }
        }

        Err(errors)
    }

    pub async fn broadcast_without_retry<'a, F, G, H>(
        &'a self,
        func: F,
    ) -> Vec<Result<H, EngineError>>
    where
        F: Fn(&'a Engine<BuilderApi>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let func = &func;
        let futures = self.builders.iter().map(|engine| async move {
            func(engine).await.map_err(|error| {
                debug!(
                    self.log,
                    "Builder call failed";
                    "error" => ?error,
                    "id" => &engine.id
                );
                EngineError::Api {
                    id: engine.id.clone(),
                    error,
                }
            })
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
