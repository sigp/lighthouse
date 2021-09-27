use engine_api::{Error as ApiError, *};
use engines::{Engine, EngineError, Engines};
use sensitive_url::SensitiveUrl;
use slog::{crit, Logger};
use std::future::Future;
use task_executor::TaskExecutor;

pub use engine_api::{http::HttpJsonRpc, ConsensusStatus, ExecutePayloadResponse};

mod engine_api;
mod engines;
pub mod test_utils;

#[derive(Debug)]
pub enum Error {
    ApiError(ApiError),
    EngineErrors(Vec<EngineError>),
    NotSynced,
    ShuttingDown,
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

pub struct ExecutionLayer {
    engines: Engines<HttpJsonRpc>,
    /// Allows callers to execute async tasks in a non-async environment, if they desire.
    pub executor: TaskExecutor,
    log: Logger,
}

impl ExecutionLayer {
    pub fn from_urls(
        urls: Vec<SensitiveUrl>,
        executor: TaskExecutor,
        log: Logger,
    ) -> Result<Self, Error> {
        let engines = urls
            .into_iter()
            .map(|url| {
                let id = url.to_string();
                let api = HttpJsonRpc::new(url)?;
                Ok(Engine::new(id, api))
            })
            .collect::<Result<_, ApiError>>()?;

        Ok(Self {
            engines: Engines {
                engines,
                log: log.clone(),
            },
            executor,
            log,
        })
    }
}

impl ExecutionLayer {
    /// Convenience function to allow calling async functions in a non-async context.
    pub fn block_on<'a, T, U, V>(&'a self, future: T) -> Result<V, Error>
    where
        T: Fn(&'a Self) -> U,
        U: Future<Output = Result<V, Error>>,
    {
        let runtime = self
            .executor
            .runtime()
            .upgrade()
            .ok_or(Error::ShuttingDown)?;
        runtime.block_on(future(self))
    }

    pub async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error> {
        self.engines
            .first_success(|engine| {
                engine
                    .api
                    .prepare_payload(parent_hash, timestamp, random, fee_recipient)
            })
            .await
            .map_err(Error::EngineErrors)
    }

    pub async fn execute_payload<T: EthSpec>(
        &self,
        execution_payload: &ExecutionPayload<T>,
    ) -> Result<ExecutePayloadResponse, Error> {
        let broadcast_results = self
            .engines
            .broadcast(|engine| engine.api.execute_payload(execution_payload.clone()))
            .await;

        let mut errors = vec![];
        let mut valid = 0;
        let mut invalid = 0;
        let mut syncing = 0;
        for result in broadcast_results {
            match result {
                Ok(ExecutePayloadResponse::Valid) => valid += 1,
                Ok(ExecutePayloadResponse::Invalid) => invalid += 1,
                Ok(ExecutePayloadResponse::Syncing) => syncing += 1,
                Err(e) => errors.push(e),
            }
        }

        if valid > 0 && invalid > 0 {
            crit!(
                self.log,
                "Consensus failure between execution nodes";
            );
        }

        if valid > 0 {
            Ok(ExecutePayloadResponse::Valid)
        } else if invalid > 0 {
            Ok(ExecutePayloadResponse::Invalid)
        } else if syncing > 0 {
            Ok(ExecutePayloadResponse::Syncing)
        } else {
            Err(Error::EngineErrors(errors))
        }
    }

    pub async fn consensus_validated(
        &self,
        block_hash: Hash256,
        status: ConsensusStatus,
    ) -> Result<(), Error> {
        let broadcast_results = self
            .engines
            .broadcast(|engine| engine.api.consensus_validated(block_hash, status))
            .await;

        if broadcast_results.iter().any(Result::is_ok) {
            Ok(())
        } else {
            Err(Error::EngineErrors(
                broadcast_results
                    .into_iter()
                    .filter_map(Result::err)
                    .collect(),
            ))
        }
    }
}
