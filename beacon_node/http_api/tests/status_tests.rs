//! Tests related to the beacon node's sync status
use beacon_chain::{
    test_utils::{AttestationStrategy, BlockStrategy, SyncCommitteeStrategy},
    BlockError,
};
use eth2::StatusCode;
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use http_api::test_utils::InteractiveTester;
use types::{EthSpec, ExecPayload, ForkName, MinimalEthSpec, Slot};

type E = MinimalEthSpec;

/// Create a new test environment that is post-merge with `chain_depth` blocks.
async fn post_merge_tester(chain_depth: u64, validator_count: u64) -> InteractiveTester<E> {
    // Test using latest fork so that we simulate conditions as similar to mainnet as possible.
    let mut spec = ForkName::latest().make_genesis_spec(E::default_spec());
    spec.terminal_total_difficulty = 1.into();

    let tester = InteractiveTester::<E>::new(Some(spec), validator_count as usize).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();
    let execution_ctx = mock_el.server.ctx.clone();

    // Move to terminal block.
    mock_el.server.all_payloads_valid();
    execution_ctx
        .execution_block_generator
        .write()
        .move_to_terminal_block()
        .unwrap();

    // Create some chain depth.
    harness.advance_slot();
    harness
        .extend_chain_with_sync(
            chain_depth as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
            SyncCommitteeStrategy::AllValidators,
        )
        .await;
    tester
}

/// Check `syncing` endpoint when the EL is syncing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn el_syncing_then_synced() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // EL syncing
    mock_el.server.set_syncing_response(Ok(true));
    mock_el.el.upcheck().await;

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert_eq!(api_response.el_offline, Some(false));
    assert_eq!(api_response.is_optimistic, Some(false));
    assert_eq!(api_response.is_syncing, false);

    // EL synced
    mock_el.server.set_syncing_response(Ok(false));
    mock_el.el.upcheck().await;

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert_eq!(api_response.el_offline, Some(false));
    assert_eq!(api_response.is_optimistic, Some(false));
    assert_eq!(api_response.is_syncing, false);
}

/// Check `syncing` endpoint when the EL is offline (errors on upcheck).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn el_offline() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // EL offline
    mock_el.server.set_syncing_response(Err("offline".into()));
    mock_el.el.upcheck().await;

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert_eq!(api_response.el_offline, Some(true));
    assert_eq!(api_response.is_optimistic, Some(false));
    assert_eq!(api_response.is_syncing, false);
}

/// Check `syncing` endpoint when the EL errors on newPaylod but is not fully offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn el_error_on_new_payload() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // Make a block.
    let pre_state = harness.get_current_state();
    let (block, _) = harness
        .make_block(pre_state, Slot::new(num_blocks + 1))
        .await;
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .unwrap()
        .block_hash();

    // Make sure `newPayload` errors for the new block.
    mock_el
        .server
        .set_new_payload_error(block_hash, "error".into());

    // Attempt to process the block, which should error.
    harness.advance_slot();
    assert!(matches!(
        harness.process_block_result(block.clone()).await,
        Err(BlockError::ExecutionPayloadError(_))
    ));

    // The EL should now be *offline* according to the API.
    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert_eq!(api_response.el_offline, Some(true));
    assert_eq!(api_response.is_optimistic, Some(false));
    assert_eq!(api_response.is_syncing, false);

    // Processing a block successfully should remove the status.
    mock_el.server.set_new_payload_status(
        block_hash,
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: Some(block_hash),
            validation_error: None,
        },
    );
    harness.process_block_result(block).await.unwrap();

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert_eq!(api_response.el_offline, Some(false));
    assert_eq!(api_response.is_optimistic, Some(false));
    assert_eq!(api_response.is_syncing, false);
}

/// Check `node health` endpoint when the EL is offline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_health_el_offline() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // EL offline
    mock_el.server.set_syncing_response(Err("offline".into()));
    mock_el.el.upcheck().await;

    let status = tester.client.get_node_health().await;
    match status {
        Ok(_) => {
            panic!("should return 503 error status code");
        }
        Err(e) => {
            assert_eq!(e.status().unwrap(), 503);
        }
    }
}

/// Check `node health` endpoint when the EL is online and synced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_health_el_online_and_synced() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // EL synced
    mock_el.server.set_syncing_response(Ok(false));
    mock_el.el.upcheck().await;

    let status = tester.client.get_node_health().await;
    match status {
        Ok(response) => {
            assert_eq!(response, StatusCode::OK);
        }
        Err(_) => {
            panic!("should return 200 status code");
        }
    }
}

/// Check `node health` endpoint when the EL is online but not synced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_health_el_online_and_not_synced() {
    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // EL not synced
    harness.advance_slot();
    mock_el.server.all_payloads_syncing(true);
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let status = tester.client.get_node_health().await;
    match status {
        Ok(response) => {
            assert_eq!(response, StatusCode::PARTIAL_CONTENT);
        }
        Err(_) => {
            panic!("should return 206 status code");
        }
    }
}
