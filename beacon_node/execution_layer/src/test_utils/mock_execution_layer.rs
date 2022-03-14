use crate::{
    test_utils::{MockServer, DEFAULT_TERMINAL_BLOCK, DEFAULT_TERMINAL_DIFFICULTY, JWT_SECRET},
    Config, *,
};
use environment::null_logger;
use sensitive_url::SensitiveUrl;
use std::sync::Arc;
use task_executor::TaskExecutor;
use tempfile::NamedTempFile;
use types::{Address, ChainSpec, Epoch, EthSpec, Hash256, Uint256};

pub struct ExecutionLayerRuntime {
    pub runtime: Option<Arc<tokio::runtime::Runtime>>,
    pub _runtime_shutdown: exit_future::Signal,
    pub task_executor: TaskExecutor,
    pub log: Logger,
}

impl Default for ExecutionLayerRuntime {
    fn default() -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let log = null_logger().unwrap();
        let task_executor =
            TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

        Self {
            runtime: Some(runtime),
            _runtime_shutdown: runtime_shutdown,
            task_executor,
            log,
        }
    }
}

impl Drop for ExecutionLayerRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            Arc::try_unwrap(runtime).unwrap().shutdown_background()
        }
    }
}

pub struct MockExecutionLayer<T: EthSpec> {
    pub server: MockServer<T>,
    pub el: ExecutionLayer,
    pub el_runtime: ExecutionLayerRuntime,
    pub spec: ChainSpec,
}

impl<T: EthSpec> MockExecutionLayer<T> {
    pub fn default_params() -> Self {
        Self::new(
            DEFAULT_TERMINAL_DIFFICULTY.into(),
            DEFAULT_TERMINAL_BLOCK,
            ExecutionBlockHash::zero(),
            Epoch::new(0),
        )
    }

    pub fn new(
        terminal_total_difficulty: Uint256,
        terminal_block: u64,
        terminal_block_hash: ExecutionBlockHash,
        terminal_block_hash_activation_epoch: Epoch,
    ) -> Self {
        let el_runtime = ExecutionLayerRuntime::default();
        let handle = el_runtime.runtime.as_ref().unwrap().handle();

        let mut spec = T::default_spec();
        spec.terminal_total_difficulty = terminal_total_difficulty;
        spec.terminal_block_hash = terminal_block_hash;
        spec.terminal_block_hash_activation_epoch = terminal_block_hash_activation_epoch;

        let server = MockServer::new(
            handle,
            terminal_total_difficulty,
            terminal_block,
            terminal_block_hash,
        );

        let url = SensitiveUrl::parse(&server.url()).unwrap();
        let file = NamedTempFile::new().unwrap();

        let path = file.path().into();
        std::fs::write(&path, hex::encode(JWT_SECRET)).unwrap();

        let config = Config {
            execution_endpoints: vec![url],
            secret_files: vec![path],
            suggested_fee_recipient: Some(Address::repeat_byte(42)),
            ..Default::default()
        };
        let el = ExecutionLayer::from_config(
            config,
            el_runtime.task_executor.clone(),
            el_runtime.log.clone(),
        )
        .unwrap();

        Self {
            server,
            el,
            el_runtime,
            spec,
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
        let prev_randao = Hash256::from_low_u64_be(block_number);
        let finalized_block_hash = parent_hash;

        // Insert a proposer to ensure the fork choice updated command works.
        let slot = Slot::new(0);
        let head_block_root = Hash256::repeat_byte(42);
        let validator_index = 0;
        self.el
            .insert_proposer(
                slot,
                head_block_root,
                validator_index,
                PayloadAttributes {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient: Address::repeat_byte(42),
                },
            )
            .await;

        self.el
            .notify_forkchoice_updated(
                parent_hash,
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
            )
            .await
            .unwrap();

        let validator_index = 0;
        let payload = self
            .el
            .get_payload::<T>(
                parent_hash,
                timestamp,
                prev_randao,
                finalized_block_hash,
                validator_index,
            )
            .await
            .unwrap();
        let block_hash = payload.block_hash;
        assert_eq!(payload.parent_hash, parent_hash);
        assert_eq!(payload.block_number, block_number);
        assert_eq!(payload.timestamp, timestamp);
        assert_eq!(payload.prev_randao, prev_randao);

        let status = self.el.notify_new_payload(&payload).await.unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        // Use junk values for slot/head-root to ensure there is no payload supplied.
        let slot = Slot::new(0);
        let head_block_root = Hash256::repeat_byte(13);
        self.el
            .notify_forkchoice_updated(
                block_hash,
                ExecutionBlockHash::zero(),
                slot,
                head_block_root,
            )
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
        U: Fn(ChainSpec, ExecutionLayer, Option<ExecutionBlock>) -> V,
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

        func(self.spec.clone(), self.el.clone(), terminal_block).await;
        self
    }
}
