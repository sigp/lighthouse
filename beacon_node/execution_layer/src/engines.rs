//! Provides generic behaviour for multiple execution engines, specifically fallback behaviour.

use crate::engine_api::{
    Error as EngineApiError, ForkchoiceUpdatedResponse, PayloadAttributes, PayloadId,
};
use crate::HttpJsonRpc;
use lru::LruCache;
use slog::{debug, error, info, Logger};
use std::future::Future;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{Mutex, RwLock};
use types::{Address, ExecutionBlockHash, Hash256};

/// The number of payload IDs that will be stored for each `Engine`.
///
/// Since the size of each value is small (~100 bytes) a large number is used for safety.
const PAYLOAD_ID_LRU_CACHE_SIZE: usize = 512;

/// Stores the remembered state of a engine.
#[derive(Copy, Clone, PartialEq, Debug)]
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

#[derive(Hash, PartialEq, std::cmp::Eq)]
struct PayloadIdCacheKey {
    pub head_block_hash: ExecutionBlockHash,
    pub timestamp: u64,
    pub prev_randao: Hash256,
    pub suggested_fee_recipient: Address,
}

#[derive(Debug)]
pub enum EngineError {
    Offline,
    Api { error: EngineApiError },
    BuilderApi { error: EngineApiError },
    Auth,
}

/// An execution engine.
pub struct Engine {
    pub api: HttpJsonRpc,
    payload_id_cache: Mutex<LruCache<PayloadIdCacheKey, PayloadId>>,
    state: RwLock<EngineState>,
    pub latest_forkchoice_state: RwLock<Option<ForkChoiceState>>,
    pub executor: TaskExecutor,
    pub log: Logger,
}

impl Engine {
    /// Creates a new, offline engine.
    pub fn new(api: HttpJsonRpc, executor: TaskExecutor, log: &Logger) -> Self {
        Self {
            api,
            payload_id_cache: Mutex::new(LruCache::new(PAYLOAD_ID_LRU_CACHE_SIZE)),
            state: RwLock::new(EngineState::Offline),
            latest_forkchoice_state: Default::default(),
            executor,
            log: log.clone(),
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
                );
                return;
            }

            info!(
                self.log,
                "Issuing forkchoiceUpdated";
                "forkchoice_state" => ?forkchoice_state,
            );

            // For simplicity, payload attributes are never included in this call. It may be
            // reasonable to include them in the future.
            if let Err(e) = self.api.forkchoice_updated_v1(forkchoice_state, None).await {
                debug!(
                    self.log,
                    "Failed to issue latest head to engine";
                    "error" => ?e,
                );
            }
        } else {
            debug!(
                self.log,
                "No head, not sending to engine";
            );
        }
    }

    /// Returns `true` if the engine has a "synced" status.
    pub async fn is_synced(&self) -> bool {
        *self.state.read().await == EngineState::Synced
    }

    /// Run the `EngineApi::upcheck` function if the node's last known state is not synced. This
    /// might be used to recover the node if offline.
    pub async fn upcheck(&self) {
        let state: EngineState = match self.api.upcheck().await {
            Ok(()) => {
                let mut state = self.state.write().await;

                if *state != EngineState::Synced {
                    info!(
                        self.log,
                        "Execution engine online";
                    );

                    // Send the node our latest forkchoice_state.
                    self.send_latest_forkchoice_state().await;
                } else {
                    debug!(
                        self.log,
                        "Execution engine online";
                    );
                }

                *state = EngineState::Synced;
                *state
            }
            Err(EngineApiError::IsSyncing) => {
                let mut state = self.state.write().await;
                *state = EngineState::Syncing;
                *state
            }
            Err(EngineApiError::Auth(err)) => {
                error!(
                    self.log,
                    "Failed jwt authorization";
                    "error" => ?err,
                );

                let mut state = self.state.write().await;
                *state = EngineState::AuthFailed;
                *state
            }
            Err(e) => {
                error!(
                    self.log,
                    "Error during execution engine upcheck";
                    "error" => ?e,
                );

                let mut state = self.state.write().await;
                *state = EngineState::Offline;
                *state
            }
        };

        debug!(
            self.log,
            "Execution engine upcheck complete";
            "state" => ?state,
        );
    }

    /// Run `func` on the node regardless of the node's current state.
    ///
    /// ## Note
    ///
    /// This function takes locks on `self.state`, holding a conflicting lock might cause a
    /// deadlock.
    pub async fn request<'a, F, G, H>(self: &'a Arc<Self>, func: F) -> Result<H, EngineError>
    where
        F: Fn(&'a Engine) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        match func(self).await {
            Ok(result) => {
                // Take a clone *without* holding the read-lock since the `upcheck` function will
                // take a write-lock.
                let state: EngineState = *self.state.read().await;

                // If this request just returned successfully but we don't think this node is
                // synced, check to see if it just became synced. This helps to ensure that the
                // networking stack can get fast feedback about a synced engine.
                if state != EngineState::Synced {
                    // Spawn the upcheck in another task to avoid slowing down this request.
                    let inner_self = self.clone();
                    self.executor.spawn(
                        async move { inner_self.upcheck().await },
                        "upcheck_after_success",
                    );
                }

                Ok(result)
            }
            Err(error) => {
                error!(
                    self.log,
                    "Execution engine call failed";
                    "error" => ?error,
                );

                // The node just returned an error, run an upcheck so we can update the endpoint
                // state.
                //
                // Spawn the upcheck in another task to avoid slowing down this request.
                let inner_self = self.clone();
                self.executor.spawn(
                    async move { inner_self.upcheck().await },
                    "upcheck_after_error",
                );

                Err(EngineError::Api { error })
            }
        }
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
