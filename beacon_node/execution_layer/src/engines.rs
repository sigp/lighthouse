//! Provides generic behaviour for multiple execution engines, specifically fallback behaviour.

use crate::engine_api::{EngineApi, Error as EngineApiError};
use futures::future::join_all;
use slog::{crit, debug, error, info, warn, Logger};
use std::future::Future;
use tokio::sync::RwLock;
use types::Hash256;

/// Stores the remembered state of a engine.
#[derive(Copy, Clone, PartialEq)]
enum EngineState {
    Synced,
    Offline,
    Syncing,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct ForkChoiceHead {
    pub head_block_hash: Hash256,
    pub finalized_block_hash: Hash256,
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

/// An execution engine.
pub struct Engine<T> {
    pub id: String,
    pub api: T,
    state: RwLock<EngineState>,
}

impl<T> Engine<T> {
    /// Creates a new, offline engine.
    pub fn new(id: String, api: T) -> Self {
        Self {
            id,
            api,
            state: RwLock::new(EngineState::Offline),
        }
    }
}

/// Holds multiple execution engines and provides functionality for managing them in a fallback
/// manner.
pub struct Engines<T> {
    pub engines: Vec<Engine<T>>,
    pub latest_head: RwLock<Option<ForkChoiceHead>>,
    pub log: Logger,
}

#[derive(Debug)]
pub enum EngineError {
    Offline { id: String },
    Api { id: String, error: EngineApiError },
}

impl<T: EngineApi> Engines<T> {
    pub async fn set_latest_head(&self, latest_head: ForkChoiceHead) {
        *self.latest_head.write().await = Some(latest_head);
    }

    async fn send_latest_head(&self, engine: &Engine<T>) {
        let latest_head: Option<ForkChoiceHead> = *self.latest_head.read().await;
        if let Some(head) = latest_head {
            info!(
                self.log,
                "Issuing forkchoiceUpdated";
                "head" => ?head,
                "id" => &engine.id,
            );

            if let Err(e) = engine
                .api
                .forkchoice_updated(head.head_block_hash, head.finalized_block_hash)
                .await
            {
                error!(
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

                        // Send the node our latest head.
                        self.send_latest_head(engine).await;

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

                        // Send the node our latest head, it may assist with syncing.
                        self.send_latest_head(engine).await;

                        *state_lock = EngineState::Syncing
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
            let engine_synced = *engine.state.read().await == EngineState::Synced;
            if engine_synced {
                match func(engine).await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        error!(
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
                    error!(
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
