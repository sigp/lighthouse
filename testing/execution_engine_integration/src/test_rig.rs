use crate::execution_engine::{ExecutionEngine, GenericExecutionEngine};
use execution_layer::{ExecutionLayer, PayloadAttributes, PayloadStatus};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::{Address, ChainSpec, EthSpec, ExecutionBlockHash, Hash256, MainnetEthSpec, Uint256};

const EXECUTION_ENGINE_START_TIMEOUT: Duration = Duration::from_secs(10);

struct ExecutionPair<E> {
    /// The Lighthouse `ExecutionLayer` struct, connected to the `execution_engine` via HTTP.
    execution_layer: ExecutionLayer,
    /// A handle to external EE process, once this is dropped the process will be killed.
    #[allow(dead_code)]
    execution_engine: ExecutionEngine<E>,
}

/// A rig that holds two EE processes for testing.
///
/// There are two EEs held here so that we can test out-of-order application of payloads, and other
/// edge-cases.
pub struct TestRig<E> {
    #[allow(dead_code)]
    runtime: Arc<tokio::runtime::Runtime>,
    ee_a: ExecutionPair<E>,
    ee_b: ExecutionPair<E>,
    spec: ChainSpec,
    _runtime_shutdown: exit_future::Signal,
}

impl<E: GenericExecutionEngine> TestRig<E> {
    pub fn new(generic_engine: E) -> Self {
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

        let fee_recipient = None;

        let ee_a = {
            let execution_engine = ExecutionEngine::new(generic_engine.clone());
            let urls = vec![execution_engine.http_url()];
            let execution_layer =
                ExecutionLayer::from_urls(urls, fee_recipient, executor.clone(), log.clone())
                    .unwrap();
            ExecutionPair {
                execution_engine,
                execution_layer,
            }
        };

        let ee_b = {
            let execution_engine = ExecutionEngine::new(generic_engine);
            let urls = vec![execution_engine.http_url()];
            let execution_layer =
                ExecutionLayer::from_urls(urls, fee_recipient, executor, log).unwrap();
            ExecutionPair {
                execution_engine,
                execution_layer,
            }
        };

        let mut spec = MainnetEthSpec::default_spec();
        spec.terminal_total_difficulty = Uint256::zero();

        Self {
            runtime,
            ee_a,
            ee_b,
            spec,
            _runtime_shutdown: runtime_shutdown,
        }
    }

    pub fn perform_tests_blocking(&self) {
        self.ee_a
            .execution_layer
            .block_on_generic(|_| async { self.perform_tests().await })
            .unwrap()
    }

    pub async fn wait_until_synced(&self) {
        let start_instant = Instant::now();

        for pair in [&self.ee_a, &self.ee_b] {
            loop {
                // Run the routine to check for online nodes.
                pair.execution_layer.watchdog_task().await;

                if pair.execution_layer.is_synced().await {
                    break;
                } else if start_instant + EXECUTION_ENGINE_START_TIMEOUT > Instant::now() {
                    sleep(Duration::from_millis(500)).await;
                } else {
                    panic!("timeout waiting for execution engines to come online")
                }
            }
        }
    }

    pub async fn perform_tests(&self) {
        self.wait_until_synced().await;

        /*
         * Read the terminal block hash from both pairs, check it's equal.
         */

        let terminal_pow_block_hash = self
            .ee_a
            .execution_layer
            .get_terminal_pow_block_hash(&self.spec)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            terminal_pow_block_hash,
            self.ee_b
                .execution_layer
                .get_terminal_pow_block_hash(&self.spec)
                .await
                .unwrap()
                .unwrap()
        );

        /*
         * Execution Engine A:
         *
         * Produce a valid payload atop the terminal block.
         */

        let parent_hash = terminal_pow_block_hash;
        let timestamp = timestamp_now();
        let random = Hash256::zero();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let proposer_index = 0;
        let valid_payload = self
            .ee_a
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
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain, before submitting a
         * `notify_new_payload`.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = None;
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Syncing);

        /*
         * Execution Engine A:
         *
         * Provide the valid payload back to the EE again.
         */

        let status = self
            .ee_a
            .execution_layer
            .notify_new_payload(&valid_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain.
         *
         * Do not provide payload attributes (we'll test that later).
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = None;
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine A:
         *
         * Provide an invalidated payload to the EE.
         */

        let mut invalid_payload = valid_payload.clone();
        invalid_payload.random = Hash256::from_low_u64_be(42);
        let status = self
            .ee_a
            .execution_layer
            .notify_new_payload(&invalid_payload)
            .await
            .unwrap();
        assert!(matches!(status, PayloadStatus::InvalidBlockHash { .. }));

        /*
         * Execution Engine A:
         *
         * Produce another payload atop the previous one.
         */

        let parent_hash = valid_payload.block_hash;
        let timestamp = valid_payload.timestamp + 1;
        let random = Hash256::zero();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let proposer_index = 0;
        let second_payload = self
            .ee_a
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
         * Execution Engine A:
         *
         * Provide the second payload back to the EE again.
         */

        let status = self
            .ee_a
            .execution_layer
            .notify_new_payload(&second_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain, providing payload attributes.
         */
        let head_block_hash = valid_payload.block_hash;
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = Some(PayloadAttributes {
            timestamp: second_payload.timestamp + 1,
            random: Hash256::zero(),
            suggested_fee_recipient: Address::zero(),
        });
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine B:
         *
         * Provide the second payload, without providing the first.
         */
        let status = self
            .ee_b
            .execution_layer
            .notify_new_payload(&second_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Accepted);

        /*
         * Execution Engine B:
         *
         * Set the second payload as the head, without providing payload attributes.
         */
        let head_block_hash = second_payload.block_hash;
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = None;
        let status = self
            .ee_b
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Syncing);

        /*
         * Execution Engine B:
         *
         * Provide the first payload to the EE.
         */

        let status = self
            .ee_b
            .execution_layer
            .notify_new_payload(&valid_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine B:
         *
         * Provide the second payload, now the first has been provided.
         */
        let status = self
            .ee_b
            .execution_layer
            .notify_new_payload(&second_payload)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);

        /*
         * Execution Engine B:
         *
         * Set the second payload as the head, without providing payload attributes.
         */
        let head_block_hash = second_payload.block_hash;
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = None;
        let status = self
            .ee_b
            .execution_layer
            .notify_forkchoice_updated(head_block_hash, finalized_block_hash, payload_attributes)
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);
    }
}

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
