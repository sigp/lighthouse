use crate::execution_engine::{ExecutionEngine, GenericExecutionEngine};
use execution_layer::{ExecutionLayer, PayloadAttributes, PayloadStatusV1Status};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::{Address, ChainSpec, EthSpec, Hash256, MainnetEthSpec, Uint256};

const EXECUTION_ENGINE_START_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TestRig<E> {
    #[allow(dead_code)]
    runtime: Arc<tokio::runtime::Runtime>,
    execution_layer: ExecutionLayer,
    #[allow(dead_code)]
    execution_engine: ExecutionEngine<E>,
    spec: ChainSpec,
    _runtime_shutdown: exit_future::Signal,
}

impl<E: GenericExecutionEngine> TestRig<E> {
    pub fn new(execution_engine: ExecutionEngine<E>) -> Self {
        let log = environment::null_logger().unwrap();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

        let mut urls = vec![];
        urls.push(execution_engine.http_url());

        let fee_recipient = None;
        let execution_layer =
            ExecutionLayer::from_urls(urls, fee_recipient, executor, log).unwrap();

        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_total_difficulty = Uint256::zero();

        Self {
            runtime,
            execution_layer,
            execution_engine,
            spec,
            _runtime_shutdown: runtime_shutdown,
        }
    }

    pub fn perform_tests_blocking(&self) {
        self.execution_layer
            .block_on_generic(|_| async { self.perform_tests().await })
            .unwrap()
    }

    pub async fn wait_until_synced(&self) {
        let start_instant = Instant::now();

        loop {
            // Run the routine to check for online nodes.
            self.execution_layer.watchdog_task().await;

            if self.execution_layer.is_synced().await {
                break;
            } else {
                if start_instant + EXECUTION_ENGINE_START_TIMEOUT > Instant::now() {
                    sleep(Duration::from_millis(500)).await;
                } else {
                    panic!("timeout waiting for execution engines to come online")
                }
            }
        }
    }

    pub async fn perform_tests(&self) {
        self.wait_until_synced().await;

        let terminal_pow_block_hash = self
            .execution_layer
            .get_terminal_pow_block_hash(&self.spec)
            .await
            .unwrap()
            .unwrap();

        /*
         * Produce a valid payload atop the terminal block.
         */

        let parent_hash = terminal_pow_block_hash;
        let timestamp = timestamp_now();
        let random = Hash256::zero();
        let finalized_block_hash = Hash256::zero();
        let proposer_index = 0;
        let valid_payload = self
            .execution_layer
            .get_payload::<MainnetEthSpec>(
                parent_hash,
                timestamp,
                random,
                finalized_block_hash,
                proposer_index,
            )
            .await
            .unwrap();

        /*
         * Indicate that the payload is the head of the chain, before submitting a
         * `notify_new_payload`.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = None;
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Syncing);

        /*
         * Provide the valid payload back to the EE again.
         */

        let (status, _) = self
            .execution_layer
            .notify_new_payload(&valid_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Indicate that the payload is the head of the chain.
         *
         * Do not provide payload attributes (we'll test that later).
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = None;
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Provide an invalidated payload to the EE.
         */

        let mut invalid_payload = valid_payload.clone();
        invalid_payload.random = Hash256::from_low_u64_be(42);
        let (status, _) = self
            .execution_layer
            .notify_new_payload(&invalid_payload)
            .await
            .unwrap();
        assert!(matches!(
            status,
            PayloadStatusV1Status::Invalid | PayloadStatusV1Status::InvalidBlockHash
        ));

        /*
         * Produce another payload atop the previous one.
         */

        let parent_hash = valid_payload.block_hash;
        let timestamp = valid_payload.timestamp + 1;
        let random = Hash256::zero();
        let finalized_block_hash = Hash256::zero();
        let proposer_index = 0;
        let second_payload = self
            .execution_layer
            .get_payload::<MainnetEthSpec>(
                parent_hash,
                timestamp,
                random,
                finalized_block_hash,
                proposer_index,
            )
            .await
            .unwrap();

        /*
         * Provide the second payload back to the EE again.
         */

        let (status, _) = self
            .execution_layer
            .notify_new_payload(&second_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);

        /*
         * Indicate that the payload is the head of the chain, providing payload attributes.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = Hash256::zero();
        let payload_attributes = PayloadAttributes {
            timestamp: second_payload.timestamp + 1,
            random: Hash256::zero(),
            suggested_fee_recipient: Address::zero(),
        };
        let (status, _) = self
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                finalized_block_hash,
                Some(payload_attributes),
            )
            .await
            .unwrap();
        assert_eq!(status, PayloadStatusV1Status::Valid);
    }
}

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
