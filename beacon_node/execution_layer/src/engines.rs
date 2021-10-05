//! Provides generic behaviour for multiple execution engines, specifically fallback behaviour.

use crate::engine_api::{EngineApi, Error as EngineApiError};
use futures::future::join_all;
use slog::{crit, error, info, warn, Logger};
use std::future::Future;
use tokio::sync::RwLock;

/// Indicates if the operation requires the engine to be synced before the command is sent.
pub enum RequireSynced {
    /// The engine must be synced.
    Yes,
    /// The operation can proceed without the engine being synced.
    No,
}

/// Stores the remembered state of a engine.
#[derive(Copy, Clone, PartialEq)]
enum EngineState {
    Synced,
    Offline,
    Syncing,
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
    pub log: Logger,
}

#[derive(Debug)]
pub enum EngineError {
    Offline { id: String },
    Api { id: String, error: EngineApiError },
}

impl<T: EngineApi> Engines<T> {
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
            let mut state = engine.state.write().await;
            if *state != EngineState::Synced {
                match engine.api.upcheck().await {
                    Ok(()) => {
                        if logging.is_enabled() {
                            info!(
                                self.log,
                                "Execution engine online";
                                "id" => &engine.id
                            );
                        }
                        *state = EngineState::Synced
                    }
                    Err(EngineApiError::IsSyncing) => {
                        if logging.is_enabled() {
                            warn!(
                                self.log,
                                "Execution engine syncing";
                                "id" => &engine.id
                            )
                        }
                        *state = EngineState::Syncing
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
            *state
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

    /// Runs `func` on all nodes concurrently, returning all results.
    ///
    /// This function might try to run `func` twice. If all nodes return an error on the first time
    /// it runs, it will try to upcheck all offline nodes and then run the function again.
    pub async fn broadcast<'a, F, G, H>(
        &'a self,
        require_synced: RequireSynced,
        func: F,
    ) -> Vec<Result<H, EngineError>>
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
            let engine_synced = *engine.state.read().await == EngineState::Synced;
            if engine_synced {
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
