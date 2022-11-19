use crate::execution_engine::{
    ExecutionEngine, GenericExecutionEngine, ACCOUNT1, ACCOUNT2, KEYSTORE_PASSWORD, PRIVATE_KEYS,
};
use crate::transactions::transactions;
use ethers_providers::Middleware;
use execution_layer::{
    BuilderParams, ChainHealth, ExecutionLayer, PayloadAttributes, PayloadAttributesV1,
    PayloadStatus,
};
use fork_choice::ForkchoiceUpdateParameters;
use reqwest::{header::CONTENT_TYPE, Client};
use sensitive_url::SensitiveUrl;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::{
    Address, ChainSpec, EthSpec, ExecutionBlockHash, ExecutionPayload, ForkName, FullPayload,
    Hash256, MainnetEthSpec, PublicKeyBytes, Slot, Uint256,
};
const EXECUTION_ENGINE_START_TIMEOUT: Duration = Duration::from_secs(20);

struct ExecutionPair<E, T: EthSpec> {
    /// The Lighthouse `ExecutionLayer` struct, connected to the `execution_engine` via HTTP.
    execution_layer: ExecutionLayer<T>,
    /// A handle to external EE process, once this is dropped the process will be killed.
    #[allow(dead_code)]
    execution_engine: ExecutionEngine<E>,
}

/// A rig that holds two EE processes for testing.
///
/// There are two EEs held here so that we can test out-of-order application of payloads, and other
/// edge-cases.
pub struct TestRig<E, T: EthSpec = MainnetEthSpec> {
    #[allow(dead_code)]
    runtime: Arc<tokio::runtime::Runtime>,
    ee_a: ExecutionPair<E, T>,
    ee_b: ExecutionPair<E, T>,
    spec: ChainSpec,
    _runtime_shutdown: exit_future::Signal,
}

/// Import a private key into the execution engine and unlock it so that we can
/// make transactions with the corresponding account.
async fn import_and_unlock(http_url: SensitiveUrl, priv_keys: &[&str], password: &str) {
    for priv_key in priv_keys {
        let body = json!(
            {
                "jsonrpc":"2.0",
                "method":"personal_importRawKey",
                "params":[priv_key, password],
                "id":1
            }
        );

        let client = Client::builder().build().unwrap();
        let request = client
            .post(http_url.full.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        let response: Value = request
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();

        let account = response.get("result").unwrap().as_str().unwrap();

        let body = json!(
            {
                "jsonrpc":"2.0",
                "method":"personal_unlockAccount",
                "params":[account, password],
                "id":1
            }
        );

        let request = client
            .post(http_url.full.clone())
            .header(CONTENT_TYPE, "application/json")
            .json(&body);

        let _response: Value = request
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
    }
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
            let urls = vec![execution_engine.http_auth_url()];

            let config = execution_layer::Config {
                execution_endpoints: urls,
                secret_files: vec![],
                suggested_fee_recipient: Some(Address::repeat_byte(42)),
                default_datadir: execution_engine.datadir(),
                ..Default::default()
            };
            let execution_layer =
                ExecutionLayer::from_config(config, executor.clone(), log.clone()).unwrap();
            ExecutionPair {
                execution_engine,
                execution_layer,
            }
        };

        let ee_b = {
            let execution_engine = ExecutionEngine::new(generic_engine);
            let urls = vec![execution_engine.http_auth_url()];

            let config = execution_layer::Config {
                execution_endpoints: urls,
                secret_files: vec![],
                suggested_fee_recipient: fee_recipient,
                default_datadir: execution_engine.datadir(),
                ..Default::default()
            };
            let execution_layer =
                ExecutionLayer::from_config(config, executor, log.clone()).unwrap();
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
        self.runtime
            .handle()
            .block_on(async { self.perform_tests().await });
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

        // Import and unlock all private keys to sign transactions
        let _ = futures::future::join_all([&self.ee_a, &self.ee_b].iter().map(|ee| {
            import_and_unlock(
                ee.execution_engine.http_url(),
                &PRIVATE_KEYS,
                KEYSTORE_PASSWORD,
            )
        }))
        .await;

        // We hardcode the accounts here since some EEs start with a default unlocked account
        let account1 = ethers_core::types::Address::from_slice(&hex::decode(ACCOUNT1).unwrap());
        let account2 = ethers_core::types::Address::from_slice(&hex::decode(ACCOUNT2).unwrap());

        /*
         * Check the transition config endpoint.
         */
        for ee in [&self.ee_a, &self.ee_b] {
            ee.execution_layer
                .exchange_transition_configuration(&self.spec)
                .await
                .unwrap();
        }

        /*
         * Read the terminal block hash from both pairs, check it's equal.
         */

        let terminal_pow_block_hash = self
            .ee_a
            .execution_layer
            .get_terminal_pow_block_hash(&self.spec, timestamp_now())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            terminal_pow_block_hash,
            self.ee_b
                .execution_layer
                .get_terminal_pow_block_hash(&self.spec, timestamp_now())
                .await
                .unwrap()
                .unwrap()
        );

        // Submit transactions before getting payload
        let txs = transactions::<MainnetEthSpec>(account1, account2);
        let mut pending_txs = Vec::new();
        for tx in txs.clone().into_iter() {
            let pending_tx = self
                .ee_a
                .execution_engine
                .provider
                .send_transaction(tx, None)
                .await
                .unwrap();
            pending_txs.push(pending_tx);
        }

        /*
         * Execution Engine A:
         *
         * Produce a valid payload atop the terminal block.
         */

        let parent_hash = terminal_pow_block_hash;
        let timestamp = timestamp_now();
        let prev_randao = Hash256::zero();
        let head_root = Hash256::zero();
        let justified_block_hash = ExecutionBlockHash::zero();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root,
            head_hash: Some(parent_hash),
            justified_hash: Some(justified_block_hash),
            finalized_hash: Some(finalized_block_hash),
        };
        let proposer_index = 0;

        let prepared = self
            .ee_a
            .execution_layer
            .insert_proposer(
                Slot::new(1), // Insert proposer for the next slot
                head_root,
                proposer_index,
                PayloadAttributes::V1(PayloadAttributesV1 {
                    timestamp,
                    prev_randao,
                    suggested_fee_recipient: Address::zero(),
                }),
            )
            .await;

        assert!(!prepared, "Inserting proposer for the first time");

        // Make a fcu call with the PayloadAttributes that we inserted previously
        let prepare = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(
                parent_hash,
                justified_block_hash,
                finalized_block_hash,
                Slot::new(0),
                Hash256::zero(),
            )
            .await
            .unwrap();

        assert_eq!(prepare, PayloadStatus::Valid);

        // Add a delay to give the EE sufficient time to pack the
        // submitted transactions into a payload.
        // This is required when running on under resourced nodes and
        // in CI.
        sleep(Duration::from_secs(3)).await;

        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot: Slot::new(0),
            chain_health: ChainHealth::Healthy,
        };
        let valid_payload = self
            .ee_a
            .execution_layer
            .get_payload::<FullPayload<MainnetEthSpec>>(
                parent_hash,
                timestamp,
                prev_randao,
                proposer_index,
                forkchoice_update_params,
                builder_params,
                // FIXME: think about how to test other forks
                ForkName::Merge,
                #[cfg(feature = "withdrawals")]
                None,
                &self.spec,
            )
            .await
            .unwrap()
            .to_payload()
            .execution_payload();

        /*
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain, before submitting a
         * `notify_new_payload`.
         */
        let head_block_hash = valid_payload.block_hash();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let slot = Slot::new(42);
        let head_block_root = Hash256::repeat_byte(42);
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                justified_block_hash,
                finalized_block_hash,
                slot,
                head_block_root,
            )
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
        check_payload_reconstruction(&self.ee_a, &valid_payload).await;

        /*
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain.
         *
         * Do not provide payload attributes (we'll test that later).
         */
        let head_block_hash = valid_payload.block_hash();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let slot = Slot::new(42);
        let head_block_root = Hash256::repeat_byte(42);
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                justified_block_hash,
                finalized_block_hash,
                slot,
                head_block_root,
            )
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);
        assert_eq!(valid_payload.transactions().len(), pending_txs.len());

        // Verify that all submitted txs were successful
        for pending_tx in pending_txs {
            let tx_receipt = pending_tx.await.unwrap().unwrap();
            assert_eq!(
                tx_receipt.status,
                Some(1.into()),
                "Tx index {} has invalid status ",
                tx_receipt.transaction_index
            );
        }

        /*
         * Execution Engine A:
         *
         * Provide an invalidated payload to the EE.
         */

        let mut invalid_payload = valid_payload.clone();
        *invalid_payload.prev_randao_mut() = Hash256::from_low_u64_be(42);
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

        let parent_hash = valid_payload.block_hash();
        let timestamp = valid_payload.timestamp() + 1;
        let prev_randao = Hash256::zero();
        let proposer_index = 0;
        let builder_params = BuilderParams {
            pubkey: PublicKeyBytes::empty(),
            slot: Slot::new(0),
            chain_health: ChainHealth::Healthy,
        };
        let second_payload = self
            .ee_a
            .execution_layer
            .get_payload::<FullPayload<MainnetEthSpec>>(
                parent_hash,
                timestamp,
                prev_randao,
                proposer_index,
                forkchoice_update_params,
                builder_params,
                // FIXME: think about how to test other forks
                ForkName::Merge,
                #[cfg(feature = "withdrawals")]
                None,
                &self.spec,
            )
            .await
            .unwrap()
            .to_payload()
            .execution_payload();

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
        check_payload_reconstruction(&self.ee_a, &second_payload).await;

        /*
         * Execution Engine A:
         *
         * Indicate that the payload is the head of the chain, providing payload attributes.
         */
        let head_block_hash = valid_payload.block_hash();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let payload_attributes = PayloadAttributes::V1(PayloadAttributesV1 {
            timestamp: second_payload.timestamp() + 1,
            prev_randao: Hash256::zero(),
            suggested_fee_recipient: Address::zero(),
        });
        let slot = Slot::new(42);
        let head_block_root = Hash256::repeat_byte(100);
        let validator_index = 0;
        self.ee_a
            .execution_layer
            .insert_proposer(slot, head_block_root, validator_index, payload_attributes)
            .await;
        let status = self
            .ee_a
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                justified_block_hash,
                finalized_block_hash,
                slot,
                head_block_root,
            )
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
        // TODO: we should remove the `Accepted` status here once Geth fixes it
        assert!(matches!(
            status,
            PayloadStatus::Syncing | PayloadStatus::Accepted
        ));

        /*
         * Execution Engine B:
         *
         * Set the second payload as the head, without providing payload attributes.
         */
        let head_block_hash = second_payload.block_hash();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let slot = Slot::new(42);
        let head_block_root = Hash256::repeat_byte(42);
        let status = self
            .ee_b
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                justified_block_hash,
                finalized_block_hash,
                slot,
                head_block_root,
            )
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
        check_payload_reconstruction(&self.ee_b, &valid_payload).await;

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
        check_payload_reconstruction(&self.ee_b, &second_payload).await;

        /*
         * Execution Engine B:
         *
         * Set the second payload as the head, without providing payload attributes.
         */
        let head_block_hash = second_payload.block_hash();
        let finalized_block_hash = ExecutionBlockHash::zero();
        let slot = Slot::new(42);
        let head_block_root = Hash256::repeat_byte(42);
        let status = self
            .ee_b
            .execution_layer
            .notify_forkchoice_updated(
                head_block_hash,
                justified_block_hash,
                finalized_block_hash,
                slot,
                head_block_root,
            )
            .await
            .unwrap();
        assert_eq!(status, PayloadStatus::Valid);
    }
}

/// Check that the given payload can be re-constructed by fetching it from the EE.
///
/// Panic if payload reconstruction fails.
async fn check_payload_reconstruction<E: GenericExecutionEngine>(
    ee: &ExecutionPair<E, MainnetEthSpec>,
    payload: &ExecutionPayload<MainnetEthSpec>,
) {
    let reconstructed = ee
        .execution_layer
        .get_payload_by_block_hash(payload.block_hash())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reconstructed, *payload);
}

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
