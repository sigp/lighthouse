use crate::engine_api::{EngineApi, Error as EngineApiError};
use futures::future::join_all;
use slog::{crit, error, info, warn, Logger};
use std::future::Future;
use tokio::sync::RwLock;

#[derive(Copy, Clone, PartialEq)]
enum EngineState {
    Online,
    Offline,
}

impl EngineState {
    fn set_online(&mut self) {
        *self = EngineState::Online
    }

    fn set_offline(&mut self) {
        *self = EngineState::Offline
    }

    fn is_online(&self) -> bool {
        *self == EngineState::Online
    }

    fn is_offline(&self) -> bool {
        *self == EngineState::Offline
    }
}

pub struct Engine<T> {
    pub id: String,
    pub api: T,
    state: RwLock<EngineState>,
}

impl<T> Engine<T> {
    pub fn new(id: String, api: T) -> Self {
        Self {
            id,
            api,
            state: RwLock::new(EngineState::Offline),
        }
    }
}

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
    async fn upcheck_offline(&self) {
        let upcheck_futures = self.engines.iter().map(|engine| async move {
            let mut state = engine.state.write().await;
            if state.is_offline() {
                match engine.api.upcheck().await {
                    Ok(()) => {
                        info!(
                            self.log,
                            "Execution engine online";
                            "id" => &engine.id
                        );
                        state.set_online()
                    }
                    Err(e) => {
                        warn!(
                            self.log,
                            "Execution engine offline";
                            "error" => ?e,
                            "id" => &engine.id
                        )
                    }
                }
            }
            *state
        });

        let num_online = join_all(upcheck_futures)
            .await
            .into_iter()
            .filter(|state: &EngineState| state.is_online())
            .count();

        if num_online == 0 {
            crit!(
                self.log,
                "No execution engines online";
            )
        }
    }

    pub async fn first_success<'a, F, G, H>(&'a self, func: F) -> Result<H, Vec<EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G + Copy,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        match self.first_success_without_retry(func).await {
            Ok(result) => Ok(result),
            Err(mut first_errors) => {
                // Try to recover some nodes.
                self.upcheck_offline().await;
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
            let engine_online = engine.state.read().await.is_online();
            if engine_online {
                match func(engine).await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        error!(
                            self.log,
                            "Execution engine call failed";
                            "error" => ?error,
                            "id" => &engine.id
                        );
                        engine.state.write().await.set_offline();
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

    pub async fn broadcast<'a, F, G, H>(&'a self, func: F) -> Vec<Result<H, EngineError>>
    where
        F: Fn(&'a Engine<T>) -> G,
        G: Future<Output = Result<H, EngineApiError>>,
    {
        let func = &func;
        let futures = self.engines.iter().map(|engine| async move {
            let engine_online = engine.state.read().await.is_online();
            if engine_online {
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
