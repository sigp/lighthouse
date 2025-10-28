use super::*;
use crate::sync::block_lookups::common::ResponseType;
use lighthouse_network::rpc::{RPCError, RpcErrorResponse};
use lighthouse_network::service::api_types::SyncRequestId;
use types::{ExecutionBlockHash, ExecutionProof, ExecutionProofId, Hash256, Slot};

/// Test successful execution proof fetch and verification
#[test]
fn test_proof_lookup_happy_path() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Get execution payload hash from the block
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    // Trigger the unknown block (which should trigger proof request)
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);

    // Expect block request
    let block_id = rig.expect_block_lookup_request(block_root);

    // Send the block
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    // Now expect proof request
    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Send all requested proofs
    // TODO(zkproofs): We should use min_required instead of hardcoding 2 proofs here
    let proof_ids = vec![
        ExecutionProofId::new(0).unwrap(),
        ExecutionProofId::new(1).unwrap(),
    ];
    rig.complete_single_lookup_proof_download(proof_id, peer_id, block_root, block_hash, proof_ids);

    // Proofs should be processed
    rig.expect_block_process(ResponseType::ExecutionProof);

    // Block should be imported
    rig.proof_component_processed_imported(block_root);
    rig.expect_empty_network();
    rig.expect_no_active_lookups();
}

/// Test that empty proof response results in peer penalization
#[test]
fn test_proof_lookup_empty_response() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Peer sends stream terminator with no proofs
    rig.single_lookup_proof_response(proof_id, peer_id, None);

    // Peer should be penalized for not providing proofs
    rig.expect_penalty(peer_id, "NotEnoughResponsesReturned");

    // Should retry with different peer
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test partial proof response (peer doesn't have all requested proofs)
#[test]
fn test_proof_lookup_partial_response() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Requested 2 proofs but peer only sends 1
    let proof_0 = Arc::new(
        ExecutionProof::new(
            ExecutionProofId::new(0).unwrap(),
            Slot::new(0),
            block_hash,
            block_root,
            vec![1, 2, 3],
        )
        .unwrap(),
    );

    rig.single_lookup_proof_response(proof_id, peer_id, Some(proof_0));
    rig.single_lookup_proof_response(proof_id, peer_id, None); // End stream early

    // Should penalize peer for not providing all requested proofs
    rig.expect_penalty(peer_id, "NotEnoughResponsesReturned");

    // Should retry with another peer
    let new_peer = rig.new_connected_peer();
    let retry_proof_id = rig.expect_proof_lookup_request(block_root);

    // Complete with all proofs
    rig.complete_single_lookup_proof_download(
        retry_proof_id,
        new_peer,
        block_root,
        block_hash,
        vec![
            ExecutionProofId::new(0).unwrap(),
            ExecutionProofId::new(1).unwrap(),
        ],
    );

    rig.expect_block_process(ResponseType::ExecutionProof);
    rig.proof_component_processed_imported(block_root);
    rig.expect_no_active_lookups();
}

/// Test unrequested proof triggers penalization
#[test]
fn test_proof_lookup_unrequested_proof() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Requested proofs 0, 1 but peer sends proofs 5 (unrequested)
    let unrequested_proof = Arc::new(
        ExecutionProof::new(
            ExecutionProofId::new(5).unwrap(),
            Slot::new(0),
            block_hash,
            block_root,
            vec![1, 2, 3],
        )
        .unwrap(),
    );

    rig.single_lookup_proof_response(proof_id, peer_id, Some(unrequested_proof));

    // Should penalize peer for sending unrequested data
    rig.expect_penalty(peer_id, "UnrequestedProof");

    // Should retry
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test duplicate proofs triggers penalization
#[test]
fn test_proof_lookup_duplicate_proof() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Send proof 0 twice
    let proof_0_a = Arc::new(
        ExecutionProof::new(
            ExecutionProofId::new(0).unwrap(),
            Slot::new(0),
            block_hash,
            block_root,
            vec![1, 2, 3],
        )
        .unwrap(),
    );
    // TODO(zkproofs): In this case we have the same proofID but different proof_data
    // zkVMs should be deterministic, so if this happens there is likely an issue somewhere
    let proof_0_b = Arc::new(
        ExecutionProof::new(
            ExecutionProofId::new(0).unwrap(),
            Slot::new(0),
            block_hash,
            block_root,
            vec![4, 5, 6], // Different data
        )
        .unwrap(),
    );

    rig.single_lookup_proof_response(proof_id, peer_id, Some(proof_0_a));
    rig.single_lookup_proof_response(proof_id, peer_id, Some(proof_0_b));

    // Should penalize peer for duplicate proof
    rig.expect_penalty(peer_id, "DuplicatedProof");

    // Should retry
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test wrong block root in proof triggers penalization
#[test]
fn test_proof_lookup_wrong_block_root() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let wrong_root = Hash256::random();
    let peer_id = rig.new_connected_peer();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Send proof with wrong block_root
    let wrong_proof = Arc::new(
        ExecutionProof::new(
            ExecutionProofId::new(0).unwrap(),
            Slot::new(0),
            block_hash,
            wrong_root,
            vec![1, 2, 3],
        )
        .unwrap(),
    );

    rig.single_lookup_proof_response(proof_id, peer_id, Some(wrong_proof));

    // Should penalize peer
    rig.expect_penalty(peer_id, "UnrequestedBlockRoot");

    // Should retry
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test proof request timeout
#[test]
fn test_proof_lookup_timeout() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Simulate timeout by sending error
    rig.send_sync_message(SyncMessage::RpcError {
        sync_request_id: SyncRequestId::SingleExecutionProof { id: proof_id },
        peer_id,
        error: RPCError::ErrorResponse(RpcErrorResponse::ServerError, "timeout".to_string()),
    });

    // Should penalize peer for timeout
    rig.expect_penalty(peer_id, "rpc_error");

    // Should retry with different peer
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test peer disconnection during proof request
#[test]
fn test_proof_lookup_peer_disconnected() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Peer disconnects
    rig.send_sync_message(SyncMessage::RpcError {
        sync_request_id: SyncRequestId::SingleExecutionProof { id: proof_id },
        peer_id,
        error: RPCError::Disconnected,
    });

    // Should retry with different peer (no penalty for disconnect)
    let _new_peer = rig.new_connected_peer();
    rig.expect_proof_lookup_request(block_root);
}

/// Test multiple retries on failure
#[test]
fn test_proof_lookup_multiple_retries() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);

    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    // First attempt - empty response
    let proof_id_1 = rig.expect_proof_lookup_request(block_root);
    rig.single_lookup_proof_response(proof_id_1, peer_id, None);
    rig.expect_penalty(peer_id, "NotEnoughResponsesReturned");

    // Second attempt - different peer, also fails
    let peer_id_2 = rig.new_connected_peer();
    let proof_id_2 = rig.expect_proof_lookup_request(block_root);
    rig.single_lookup_proof_response(proof_id_2, peer_id_2, None);
    rig.expect_penalty(peer_id_2, "NotEnoughResponsesReturned");

    // Third attempt - succeeds
    let peer_id_3 = rig.new_connected_peer();
    let proof_id_3 = rig.expect_proof_lookup_request(block_root);
    rig.complete_single_lookup_proof_download(
        proof_id_3,
        peer_id_3,
        block_root,
        block_hash,
        vec![
            ExecutionProofId::new(0).unwrap(),
            ExecutionProofId::new(1).unwrap(),
        ],
    );

    rig.expect_block_process(ResponseType::ExecutionProof);
    rig.proof_component_processed_imported(block_root);
    rig.expect_no_active_lookups();
}

/// Test proof lookup with no peers available
#[test]
fn test_proof_lookup_no_peers() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.into()));
    rig.expect_block_process(ResponseType::Block);

    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Peer fails and disconnects
    rig.send_sync_message(SyncMessage::RpcError {
        sync_request_id: SyncRequestId::SingleExecutionProof { id: proof_id },
        peer_id,
        error: RPCError::Disconnected,
    });

    // Disconnect the peer
    rig.peer_disconnected(peer_id);

    // Should not be able to find another peer immediately
    // The lookup should remain active waiting for peers
    assert_eq!(rig.active_single_lookups_count(), 1);
}

/// Test successful proof verification after block already has blobs
#[test]
fn test_proof_lookup_with_existing_blobs() {
    let Some(mut rig) = TestRig::test_setup_after_fulu() else {
        return;
    };

    let block = rig.rand_block();
    let block_root = block.canonical_root();
    let block_hash = block
        .message()
        .body()
        .execution_payload()
        .ok()
        .map(|p| p.execution_payload_ref().block_hash())
        .unwrap_or_else(ExecutionBlockHash::zero);
    let peer_id = rig.new_connected_peer();

    // Trigger lookup
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);

    // Get block
    let block_id = rig.expect_block_lookup_request(block_root);
    rig.single_lookup_block_response(block_id, peer_id, Some(block.clone().into()));
    rig.expect_block_process(ResponseType::Block);

    // Block might still be missing proofs even if blobs present
    // Proofs are an additional requirement
    let proof_id = rig.expect_proof_lookup_request(block_root);

    // Send proofs
    rig.complete_single_lookup_proof_download(
        proof_id,
        peer_id,
        block_root,
        block_hash,
        vec![
            ExecutionProofId::new(0).unwrap(),
            ExecutionProofId::new(1).unwrap(),
        ],
    );

    rig.expect_block_process(ResponseType::ExecutionProof);
    rig.proof_component_processed_imported(block_root);
    rig.expect_no_active_lookups();
}
