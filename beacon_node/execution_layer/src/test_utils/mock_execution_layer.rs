use crate::{
    test_utils::{MockServer, DEFAULT_TERMINAL_BLOCK, DEFAULT_TERMINAL_DIFFICULTY},
    *,
};
use environment::null_logger;
use sensitive_url::SensitiveUrl;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{Address, EthSpec, Hash256, Uint256};

pub struct MockExecutionLayer<T: EthSpec> {
    pub server: MockServer<T>,
    pub el: ExecutionLayer,
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    _runtime_shutdown: exit_future::Signal,
}

impl<T: EthSpec> MockExecutionLayer<T> {
    pub fn default_params() -> Self {
        Self::new(DEFAULT_TERMINAL_DIFFICULTY.into(), DEFAULT_TERMINAL_BLOCK)
    }

    pub fn new(terminal_total_difficulty: Uint256, terminal_block: u64) -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let log = null_logger().unwrap();
        let executor = TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

        let server = MockServer::new(runtime.handle(), terminal_total_difficulty, terminal_block);

        let url = SensitiveUrl::parse(&server.url()).unwrap();

        let el = ExecutionLayer::from_urls(
            vec![url],
            terminal_total_difficulty,
            Hash256::zero(),
            Some(Address::repeat_byte(42)),
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

    pub async fn produce_valid_execution_payload_on_head(self) -> Self {
        let latest_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        let parent_hash = latest_execution_block.block_hash();
        let block_number = latest_execution_block.block_number() + 1;
        let timestamp = block_number;
        let random = Hash256::from_low_u64_be(block_number);

        let _payload_id = self
            .el
            .prepare_payload(parent_hash, timestamp, random)
            .await
            .unwrap();

        let payload = self
            .el
            .get_payload::<T>(parent_hash, timestamp, random)
            .await
            .unwrap();
        let block_hash = payload.block_hash;
        assert_eq!(payload.parent_hash, parent_hash);
        assert_eq!(payload.block_number, block_number);
        assert_eq!(payload.timestamp, timestamp);
        assert_eq!(payload.random, random);

        let (payload_response, mut payload_handle) =
            self.el.execute_payload(&payload).await.unwrap();
        assert_eq!(payload_response, ExecutePayloadResponse::Valid);

        payload_handle.publish_async(ConsensusStatus::Valid).await;

        self.el
            .forkchoice_updated(block_hash, Hash256::zero())
            .await
            .unwrap();

        let head_execution_block = {
            let block_gen = self.server.execution_block_generator();
            block_gen.latest_block().unwrap()
        };

        assert_eq!(head_execution_block.block_number(), block_number);
        assert_eq!(head_execution_block.block_hash(), block_hash);
        assert_eq!(head_execution_block.parent_hash(), parent_hash);

        self
    }

    pub fn move_to_block_prior_to_terminal_block(self) -> Self {
        self.server
            .execution_block_generator()
            .move_to_block_prior_to_terminal_block()
            .unwrap();
        self
    }

    pub fn move_to_terminal_block(self) -> Self {
        self.server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
        self
    }

    pub async fn with_terminal_block<'a, U, V>(self, func: U) -> Self
    where
        U: Fn(ExecutionLayer, Option<ExecutionBlock>) -> V,
        V: Future<Output = ()>,
    {
        let terminal_block_number = self
            .server
            .execution_block_generator()
            .terminal_block_number;
        let terminal_block = self
            .server
            .execution_block_generator()
            .execution_block_by_number(terminal_block_number);

        func(self.el.clone(), terminal_block).await;
        self
    }

    pub fn shutdown(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            Arc::try_unwrap(runtime).unwrap().shutdown_background()
        }
    }
}

impl<T: EthSpec> Drop for MockExecutionLayer<T> {
    fn drop(&mut self) {
        self.shutdown()
    }
}
