use engine_api::{Error as ApiError, *};
use engines::{Engine, EngineError, Engines};
use sensitive_url::SensitiveUrl;
use slog::{crit, Logger};
use std::future::Future;
use std::sync::Arc;
use task_executor::TaskExecutor;

pub use engine_api::{http::HttpJsonRpc, ConsensusStatus, ExecutePayloadResponse};
pub use execute_payload_handle::ExecutePayloadHandle;

mod engine_api;
mod engines;
mod execute_payload_handle;
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

struct Inner {
    engines: Engines<HttpJsonRpc>,
    terminal_total_difficulty: Uint256,
    executor: TaskExecutor,
    log: Logger,
}

#[derive(Clone)]
pub struct ExecutionLayer {
    inner: Arc<Inner>,
}

impl ExecutionLayer {
    pub fn from_urls(
        urls: Vec<SensitiveUrl>,
        terminal_total_difficulty: Uint256,
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

        let inner = Inner {
            engines: Engines {
                engines,
                log: log.clone(),
            },
            terminal_total_difficulty,
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

    fn terminal_total_difficulty(&self) -> Uint256 {
        self.inner.terminal_total_difficulty
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
        // TODO(paul): respect the shutdown signal.
        runtime.block_on(generate_future(self))
    }

    /// Convenience function to allow calling spawning a task without waiting for the result.
    pub fn spawn<T, U>(&self, generate_future: T, name: &'static str)
    where
        T: FnOnce(Self) -> U,
        U: Future<Output = ()> + Send + 'static,
    {
        self.executor().spawn(generate_future(self.clone()), name);
    }

    pub async fn prepare_payload(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
        fee_recipient: Address,
    ) -> Result<PayloadId, Error> {
        self.engines()
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
    ) -> Result<(ExecutePayloadResponse, ExecutePayloadHandle), Error> {
        let broadcast_results = self
            .engines()
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
                self.log(),
                "Consensus failure between execution nodes";
            );
        }

        let execute_payload_response = if valid > 0 {
            ExecutePayloadResponse::Valid
        } else if invalid > 0 {
            ExecutePayloadResponse::Invalid
        } else if syncing > 0 {
            ExecutePayloadResponse::Syncing
        } else {
            return Err(Error::EngineErrors(errors));
        };

        let execute_payload_handle = ExecutePayloadHandle {
            block_hash: execution_payload.block_hash,
            execution_layer: self.clone(),
            status: None,
        };

        Ok((execute_payload_response, execute_payload_handle))
    }

    pub async fn consensus_validated(
        &self,
        block_hash: Hash256,
        status: ConsensusStatus,
    ) -> Result<(), Error> {
        let broadcast_results = self
            .engines()
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

    pub async fn forkchoice_updated(
        &self,
        head_block_hash: Hash256,
        finalized_block_hash: Hash256,
    ) -> Result<(), Error> {
        let broadcast_results = self
            .engines()
            .broadcast(|engine| {
                engine
                    .api
                    .forkchoice_updated(head_block_hash, finalized_block_hash)
            })
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

    pub async fn get_pow_block_at_total_difficulty(&self) -> Result<Option<Hash256>, Error> {
        self.engines()
            .first_success(|engine| async move {
                let mut ttd_exceeding_block = None;
                let mut block = engine
                    .api
                    .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                    .await?;

                loop {
                    if block.total_difficulty >= self.terminal_total_difficulty() {
                        ttd_exceeding_block = Some(block.block_hash);

                        block = engine.api.get_block_by_hash(block.parent_hash).await?;
                    } else {
                        return Ok::<_, ApiError>(ttd_exceeding_block);
                    }
                }
            })
            .await
            .map_err(Error::EngineErrors)
    }
}
