//! Tests related to the beacon node's sync status
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::{
    BlockError,
    test_utils::{
        AttestationStrategy, BlockStrategy, LightClientStrategy, SyncCommitteeStrategy,
        fork_name_from_env, test_spec,
    },
};
use eth2::types::ProposerPreparationData;
use execution_layer::{PayloadStatusV1, PayloadStatusV1Status};
use http_api::test_utils::InteractiveTester;
use reqwest::StatusCode;
use types::{Address, EthSpec, ExecPayload, MinimalEthSpec, Slot, Uint256};

type E = MinimalEthSpec;

/// Create a new test environment that is post-merge with `chain_depth` blocks.
async fn post_merge_tester(chain_depth: u64, validator_count: u64) -> InteractiveTester<E> {
    let mut spec = test_spec::<E>();
    spec.terminal_total_difficulty = Uint256::from(1);

    let tester = InteractiveTester::<E>::new(Some(spec), validator_count as usize).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    mock_el.server.all_payloads_valid();

    // Create some chain depth.
    harness.advance_slot();
    harness
        .extend_chain_with_sync(
            chain_depth as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
            SyncCommitteeStrategy::AllValidators,
            LightClientStrategy::Disabled,
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
    assert!(!api_response.el_offline);
    assert!(!api_response.is_optimistic);
    assert!(!api_response.is_syncing);

    // EL synced
    mock_el.server.set_syncing_response(Ok(false));
    mock_el.el.upcheck().await;

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert!(!api_response.el_offline);
    assert!(!api_response.is_optimistic);
    assert!(!api_response.is_syncing);
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
    assert!(api_response.el_offline);
    assert!(!api_response.is_optimistic);
    assert!(!api_response.is_syncing);
}

/// Check `syncing` endpoint when the EL errors on newPaylod but is not fully offline.
// Gloas blocks don't carry execution payloads — the payload arrives via an envelope,
// so newPayload is never called during block import. Skip for Gloas.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn el_error_on_new_payload() {
    if fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let num_blocks = E::slots_per_epoch() / 2;
    let num_validators = E::slots_per_epoch();
    let tester = post_merge_tester(num_blocks, num_validators).await;
    let harness = &tester.harness;
    let mock_el = harness.mock_execution_layer.as_ref().unwrap();

    // Make a block.
    let pre_state = harness.get_current_state();
    let (block_contents, _) = harness
        .make_block(pre_state, Slot::new(num_blocks + 1))
        .await;
    let (block, blobs) = block_contents;

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
        harness
            .process_block_result((block.clone(), blobs.clone()))
            .await,
        Err(BlockError::ExecutionPayloadError(_))
    ));

    // The EL should now be *offline* according to the API.
    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert!(api_response.el_offline);
    assert!(!api_response.is_optimistic);
    assert!(!api_response.is_syncing);

    // Processing a block successfully should remove the status.
    mock_el.server.set_new_payload_status(
        block_hash,
        PayloadStatusV1 {
            status: PayloadStatusV1Status::Valid,
            latest_valid_hash: Some(block_hash),
            validation_error: None,
            inclusion_list_satisfied: None,
        },
    );
    harness.process_block_result((block, blobs)).await.unwrap();

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert!(!api_response.el_offline);
    assert!(!api_response.is_optimistic);
    assert!(!api_response.is_syncing);
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
// Gloas blocks don't carry execution payloads — the payload arrives via an envelope,
// so newPayload is never called during block import and the head is not marked
// optimistic when `all_payloads_syncing(true)`. Skip for Gloas.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_health_el_online_and_not_synced() {
    if fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_execution_layer_with_a_proof_engine_is_not_offline() {
    let tester = proof_engine_tester().await;

    let api_response = tester.client.get_node_syncing().await.unwrap().data;
    assert!(!api_response.el_offline);

    assert_eq!(
        tester.client.get_node_health().await.unwrap(),
        StatusCode::OK,
        "and the node is healthy, where a missing execution layer would be a 503"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proposer_preparation_without_an_execution_layer() {
    let tester = proof_engine_tester().await;

    tester
        .client
        .post_validator_prepare_beacon_proposer(&[ProposerPreparationData {
            validator_index: 0,
            fee_recipient: Address::repeat_byte(1),
        }])
        .await
        .expect("proposer preparation should be accepted with no execution layer");
}

async fn proof_engine_tester() -> InteractiveTester<E> {
    let validator_count = E::slots_per_epoch() as usize;
    InteractiveTester::<E>::new_with_initializer_and_mutator(
        None,
        validator_count,
        Some(Box::new(move |builder| {
            builder
                .deterministic_keypairs(validator_count)
                .fresh_ephemeral_store()
                .proof_engine()
        })),
        None,
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await
}
