use engine_api::{Error as ApiError, *};
use engines::{Engine, EngineError, Engines};
use lru::LruCache;
use sensitive_url::SensitiveUrl;
use slog::{crit, Logger};
use std::future::Future;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::{Mutex, MutexGuard};

pub use engine_api::{http::HttpJsonRpc, ConsensusStatus, ExecutePayloadResponse};
pub use execute_payload_handle::ExecutePayloadHandle;

mod engine_api;
mod engines;
mod execute_payload_handle;
pub mod test_utils;

const EXECUTION_BLOCKS_LRU_CACHE_SIZE: usize = 128;

#[derive(Debug)]
pub enum Error {
    ApiError(ApiError),
    EngineErrors(Vec<EngineError>),
    NotSynced,
    ShuttingDown,
    FeeRecipientUnspecified,
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::ApiError(e)
    }
}

struct Inner {
    engines: Engines<HttpJsonRpc>,
    terminal_total_difficulty: Uint256,
    terminal_block_hash: Hash256,
    fee_recipient: Option<Address>,
    execution_blocks: Mutex<LruCache<Hash256, ExecutionBlock>>,
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
        terminal_block_hash: Hash256,
        fee_recipient: Option<Address>,
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
            terminal_block_hash,
            fee_recipient,
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

    fn terminal_total_difficulty(&self) -> Uint256 {
        self.inner.terminal_total_difficulty
    }

    fn terminal_block_hash(&self) -> Hash256 {
        self.inner.terminal_block_hash
    }

    fn fee_recipient(&self) -> Result<Address, Error> {
        self.inner
            .fee_recipient
            .ok_or(Error::FeeRecipientUnspecified)
    }

    async fn execution_blocks(&self) -> MutexGuard<'_, LruCache<Hash256, ExecutionBlock>> {
        self.inner.execution_blocks.lock().await
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
    ) -> Result<PayloadId, Error> {
        let fee_recipient = self.fee_recipient()?;
        self.engines()
            .first_success(|engine| {
                // TODO(paul): put these in a cache.
                engine
                    .api
                    .prepare_payload(parent_hash, timestamp, random, fee_recipient)
            })
            .await
            .map_err(Error::EngineErrors)
    }

    pub async fn get_payload<T: EthSpec>(
        &self,
        parent_hash: Hash256,
        timestamp: u64,
        random: Hash256,
    ) -> Result<ExecutionPayload<T>, Error> {
        let fee_recipient = self.fee_recipient()?;
        self.engines()
            .first_success(|engine| async move {
                // TODO(paul): make a cache for these IDs.
                let payload_id = engine
                    .api
                    .prepare_payload(parent_hash, timestamp, random, fee_recipient)
                    .await?;

                engine.api.get_payload(payload_id).await
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
                "method" => "execute_payload"
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

    async fn get_pow_block(
        &self,
        engine: &Engine<HttpJsonRpc>,
        hash: Hash256,
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

    pub async fn get_pow_block_hash_at_total_difficulty(&self) -> Result<Option<Hash256>, Error> {
        self.engines()
            .first_success(|engine| async move {
                let mut ttd_exceeding_block = None;
                let mut block = engine
                    .api
                    .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                    .await?
                    .ok_or(ApiError::ExecutionHeadBlockNotFound)?;

                self.execution_blocks().await.put(block.block_hash, block);

                loop {
                    if block.total_difficulty >= self.terminal_total_difficulty() {
                        ttd_exceeding_block = Some(block.block_hash);

                        block = self
                            .get_pow_block(engine, block.parent_hash)
                            .await?
                            .ok_or(ApiError::ExecutionBlockNotFound(block.parent_hash))?;
                    } else {
                        return Ok::<_, ApiError>(ttd_exceeding_block);
                    }
                }
            })
            .await
            .map_err(Error::EngineErrors)
    }

    /// Returns:
    ///
    /// - `Some(true)` if the given `block_hash` is the terminal proof-of-work block.
    /// - `Some(false)` if the given `block_hash` is *not* the terminal proof-of-work block.
    /// - `None` if the `block_hash` or its parent were not present on the execution engines.
    /// - `Err(_)` if there was an error connecting to the execution engines.
    pub async fn is_valid_terminal_pow_block_hash(
        &self,
        block_hash: Hash256,
    ) -> Result<Option<bool>, Error> {
        let broadcast_results = self
            .engines()
            .broadcast(|engine| async move {
                if let Some(pow_block) = self.get_pow_block(engine, block_hash).await? {
                    if let Some(pow_parent) =
                        self.get_pow_block(engine, pow_block.parent_hash).await?
                    {
                        return Ok(Some(
                            self.is_valid_terminal_pow_block(pow_block, pow_parent),
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

    fn is_valid_terminal_pow_block(&self, block: ExecutionBlock, parent: ExecutionBlock) -> bool {
        if block.block_hash == self.terminal_block_hash() {
            return true;
        }

        let is_total_difficulty_reached =
            block.total_difficulty >= self.terminal_total_difficulty();
        let is_parent_total_difficulty_valid =
            parent.total_difficulty < self.terminal_total_difficulty();
        is_total_difficulty_reached && is_parent_total_difficulty_valid
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{block_number_to_hash, MockServer, DEFAULT_TERMINAL_DIFFICULTY};
    use environment::null_logger;
    use types::MainnetEthSpec;

    struct SingleEngineTester {
        server: MockServer<MainnetEthSpec>,
        el: ExecutionLayer,
        runtime: Option<Arc<tokio::runtime::Runtime>>,
        _runtime_shutdown: exit_future::Signal,
    }

    impl SingleEngineTester {
        pub fn new() -> Self {
            let server = MockServer::unit_testing();
            let url = SensitiveUrl::parse(&server.url()).unwrap();
            let log = null_logger().unwrap();

            let runtime = Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap(),
            );
            let (runtime_shutdown, exit) = exit_future::signal();
            let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
            let executor =
                TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

            let el = ExecutionLayer::from_urls(
                vec![url],
                DEFAULT_TERMINAL_DIFFICULTY.into(),
                Hash256::zero(),
                None,
                executor,
                log,
            )
            .unwrap();

            Self {
                server,
                el,
                runtime: Some(runtime),
                _runtime_shutdown: runtime_shutdown,
            }
        }

        pub async fn move_to_block_prior_to_terminal_block(self) -> Self {
            {
                let mut block_gen = self.server.execution_block_generator().await;
                let target_block = block_gen.terminal_block_number.checked_sub(1).unwrap();
                block_gen.set_clock_for_block_number(target_block)
            }
            self
        }

        pub async fn move_to_terminal_block(self) -> Self {
            {
                let mut block_gen = self.server.execution_block_generator().await;
                let target_block = block_gen.terminal_block_number;
                block_gen.set_clock_for_block_number(target_block)
            }
            self
        }

        pub async fn with_terminal_block_number<'a, T, U>(self, func: T) -> Self
        where
            T: Fn(ExecutionLayer, u64) -> U,
            U: Future<Output = ()>,
        {
            let terminal_block_number = self
                .server
                .execution_block_generator()
                .await
                .terminal_block_number;
            func(self.el.clone(), terminal_block_number).await;
            self
        }

        pub fn shutdown(&mut self) {
            if let Some(runtime) = self.runtime.take() {
                Arc::try_unwrap(runtime).unwrap().shutdown_background()
            }
        }
    }

    impl Drop for SingleEngineTester {
        fn drop(&mut self) {
            self.shutdown()
        }
    }

    #[tokio::test]
    async fn finds_valid_terminal_block_hash() {
        SingleEngineTester::new()
            .move_to_block_prior_to_terminal_block()
            .await
            .with_terminal_block_number(|el, _| async move {
                assert_eq!(
                    el.get_pow_block_hash_at_total_difficulty().await.unwrap(),
                    None
                )
            })
            .await
            .move_to_terminal_block()
            .await
            .with_terminal_block_number(|el, terminal_block_number| async move {
                assert_eq!(
                    el.get_pow_block_hash_at_total_difficulty().await.unwrap(),
                    Some(block_number_to_hash(terminal_block_number))
                )
            })
            .await;
    }

    #[tokio::test]
    async fn verifies_valid_terminal_block_hash() {
        SingleEngineTester::new()
            .move_to_terminal_block()
            .await
            .with_terminal_block_number(|el, terminal_block_number| async move {
                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(block_number_to_hash(
                        terminal_block_number
                    ))
                    .await
                    .unwrap(),
                    Some(true)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_invalid_terminal_block_hash() {
        SingleEngineTester::new()
            .move_to_terminal_block()
            .await
            .with_terminal_block_number(|el, terminal_block_number| async move {
                let invalid_terminal_block = terminal_block_number.checked_sub(1).unwrap();

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(block_number_to_hash(
                        invalid_terminal_block
                    ))
                    .await
                    .unwrap(),
                    Some(false)
                )
            })
            .await;
    }

    #[tokio::test]
    async fn rejects_unknown_terminal_block_hash() {
        SingleEngineTester::new()
            .move_to_terminal_block()
            .await
            .with_terminal_block_number(|el, terminal_block_number| async move {
                let missing_terminal_block = terminal_block_number.checked_add(1).unwrap();

                assert_eq!(
                    el.is_valid_terminal_pow_block_hash(block_number_to_hash(
                        missing_terminal_block
                    ))
                    .await
                    .unwrap(),
                    None
                )
            })
            .await;
    }
}
