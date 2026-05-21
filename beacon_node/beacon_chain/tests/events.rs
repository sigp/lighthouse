use arbitrary::Arbitrary;
use beacon_chain::data_column_verification::GossipVerifiedDataColumn;
use beacon_chain::test_utils::{
    BeaconChainHarness, fork_name_from_env, generate_data_column_sidecars_from_block, test_spec,
};
use eth2::types::{EventKind, SseBlobSidecar, SseDataColumnSidecar};
use std::sync::Arc;
use types::data::FixedBlobSidecarList;
use types::{
    BlobSidecar, DataColumnSidecar, DataColumnSidecarFulu, DataColumnSidecarGloas, Domain, EthSpec,
    MinimalEthSpec, PayloadAttestationData, PayloadAttestationMessage, SignedExecutionPayloadBid,
    SignedRoot, Slot,
};

type E = MinimalEthSpec;

/// Verifies that a data column event is emitted when a gossip verified data column is received via gossip or the publish block API.
#[tokio::test]
async fn data_column_sidecar_event_on_process_gossip_data_column() {
    if fork_name_from_env().is_some_and(|f| !f.fulu_enabled()) {
        return;
    };

    let spec = Arc::new(test_spec::<E>());
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // subscribe to blob sidecar events
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut data_column_event_receiver = event_handler.subscribe_data_column_sidecar();

    // build and process a gossip verified data column
    let mut u = types::test_utils::test_unstructured();
    let sidecar = {
        let slot = Slot::new(10);
        let fork_name = harness.spec.fork_name_at_slot::<E>(slot);
        // DA checker only accepts sampling columns, so we need to create one with a sampling index.
        if fork_name.gloas_enabled() {
            let mut random_sidecar = DataColumnSidecarGloas::arbitrary(&mut u).unwrap();
            let epoch = slot.epoch(E::slots_per_epoch());
            random_sidecar.slot = slot;
            random_sidecar.index = harness.chain.sampling_columns_for_epoch(epoch)[0];

            // For gloas, the bid must be known, e.g. in the pending payload cache
            let mut bid = SignedExecutionPayloadBid::<E>::empty();
            bid.message.slot = Slot::new(10);
            harness
                .chain
                .pending_payload_cache
                .insert_bid(random_sidecar.beacon_block_root, Arc::new(bid));

            DataColumnSidecar::Gloas(random_sidecar)
        } else {
            let mut random_sidecar = DataColumnSidecarFulu::arbitrary(&mut u).unwrap();
            let epoch = slot.epoch(E::slots_per_epoch());
            random_sidecar.signed_block_header.message.slot = slot;
            random_sidecar.index = harness.chain.sampling_columns_for_epoch(epoch)[0];
            DataColumnSidecar::Fulu(random_sidecar)
        }
    };
    let gossip_verified_data_column =
        GossipVerifiedDataColumn::__new_for_testing(Arc::new(sidecar));
    let expected_sse_data_column = SseDataColumnSidecar::from_data_column_sidecar(
        gossip_verified_data_column.as_data_column(),
    );

    let _ = harness
        .chain
        .process_gossip_data_columns(vec![gossip_verified_data_column], || Ok(()))
        .await
        .unwrap();

    let sidecar_event = data_column_event_receiver.try_recv().unwrap();
    assert_eq!(
        sidecar_event,
        EventKind::DataColumnSidecar(expected_sse_data_column)
    );
}

/// Verifies that a blob event is emitted when blobs are received via RPC.
#[tokio::test]
async fn blob_sidecar_event_on_process_rpc_blobs() {
    if fork_name_from_env().is_none_or(|f| !f.deneb_enabled() || f.fulu_enabled()) {
        return;
    };

    let spec = Arc::new(test_spec::<E>());
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec)
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // subscribe to blob sidecar events
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut blob_event_receiver = event_handler.subscribe_blob_sidecar();

    // build and process multiple rpc blobs
    harness.execution_block_generator().set_min_blob_count(2);

    let head_state = harness.get_current_state();
    let slot = head_state.slot() + 1;
    let ((signed_block, opt_blobs), _) = harness.make_block(head_state, slot).await;
    let (kzg_proofs, blobs) = opt_blobs.unwrap();
    assert_eq!(blobs.len(), 2);

    let blob_1 =
        Arc::new(BlobSidecar::new(0, blobs[0].clone(), &signed_block, kzg_proofs[0]).unwrap());
    let blob_2 =
        Arc::new(BlobSidecar::new(1, blobs[1].clone(), &signed_block, kzg_proofs[1]).unwrap());

    let blobs = FixedBlobSidecarList::new(vec![Some(blob_1.clone()), Some(blob_2.clone())]);
    let expected_sse_blobs = vec![
        SseBlobSidecar::from_blob_sidecar(blob_1.as_ref()),
        SseBlobSidecar::from_blob_sidecar(blob_2.as_ref()),
    ];

    let _ = harness
        .chain
        .process_rpc_blobs(slot, blob_1.block_root(), blobs)
        .await
        .unwrap();

    let mut sse_blobs: Vec<SseBlobSidecar> = vec![];
    while let Ok(sidecar_event) = blob_event_receiver.try_recv() {
        if let EventKind::BlobSidecar(sse_blob_sidecar) = sidecar_event {
            sse_blobs.push(sse_blob_sidecar);
        } else {
            panic!("`BlobSidecar` event kind expected.");
        }
    }
    assert_eq!(sse_blobs, expected_sse_blobs);
}

#[tokio::test]
async fn data_column_sidecar_event_on_process_rpc_columns() {
    // Gloas blocks don't have blob_kzg_commitments (blobs are in the execution payload envelope).
    if fork_name_from_env().is_none_or(|f| !f.fulu_enabled())
        || fork_name_from_env().is_some_and(|f| f.gloas_enabled())
    {
        return;
    };

    let spec = Arc::new(test_spec::<E>());
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // subscribe to blob sidecar events
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut data_column_event_receiver = event_handler.subscribe_data_column_sidecar();

    // build a valid block
    harness.execution_block_generator().set_min_blob_count(1);

    let head_state = harness.get_current_state();
    let slot = head_state.slot() + 1;
    let ((signed_block, opt_blobs), _) = harness.make_block(head_state, slot).await;
    let (_, blobs) = opt_blobs.unwrap();
    assert!(!blobs.is_empty());

    // load the precomputed column sidecar to avoid computing them for every block in the tests.
    let data_column_sidecars =
        generate_data_column_sidecars_from_block(&signed_block, &harness.chain.spec);
    let sidecar = data_column_sidecars[0].clone();
    let expected_sse_data_column = SseDataColumnSidecar::from_data_column_sidecar(&sidecar);

    let _ = harness
        .chain
        .process_rpc_custody_columns(vec![sidecar])
        .await
        .unwrap();

    let sidecar_event = data_column_event_receiver.try_recv().unwrap();
    assert_eq!(
        sidecar_event,
        EventKind::DataColumnSidecar(expected_sse_data_column)
    );
}

/// Verifies that a head event is emitted when a block is imported and becomes the head.
#[tokio::test]
async fn head_event_on_block_import() {
    let spec = Arc::new(test_spec::<E>());
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // Subscribe to head events before importing the block
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut head_event_receiver = event_handler.subscribe_head();

    // Build and process a block that will become the new head
    let head_state = harness.get_current_state();
    let target_slot = head_state.slot() + 1;
    harness.advance_slot();
    let ((signed_block, blobs), _) = harness.make_block(head_state, target_slot).await;

    let block_root = signed_block.canonical_root();
    let state_root = signed_block.message().state_root();

    harness
        .process_block(target_slot, block_root, (signed_block, blobs))
        .await
        .unwrap();

    // Verify the head event was emitted with correct data
    let head_event = head_event_receiver.try_recv().unwrap();
    if let EventKind::Head(sse_head) = head_event {
        assert_eq!(sse_head.slot, target_slot);
        assert_eq!(sse_head.block, block_root);
        assert_eq!(sse_head.state, state_root);
        // execution_optimistic should be false since we're using mock execution layer
        assert!(!sse_head.execution_optimistic);
    } else {
        panic!("Expected Head event, got {:?}", head_event);
    }
}

/// Verifies that `execution_payload_gossip` fires at gossip verification time, and
/// `execution_payload` + `execution_payload_available` fire at import time.
#[tokio::test]
async fn execution_payload_envelope_events() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();

    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");

    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut gossip_receiver = event_handler.subscribe_execution_payload_gossip();
    let mut payload_receiver = event_handler.subscribe_execution_payload();
    let mut available_receiver = event_handler.subscribe_execution_payload_available();

    // Stage 1: gossip verification fires execution_payload_gossip only.
    let gossip_verified = harness
        .chain
        .verify_envelope_for_gossip(Arc::new(signed_envelope))
        .await
        .expect("envelope gossip verification should succeed");

    let gossip_event = gossip_receiver
        .try_recv()
        .expect("should receive execution_payload_gossip after gossip verification");
    if let EventKind::ExecutionPayloadGossip(sse) = gossip_event {
        assert_eq!(sse.slot, target_slot);
        assert_eq!(sse.block_root, block_root);
    } else {
        panic!(
            "Expected ExecutionPayloadGossip event, got {:?}",
            gossip_event
        );
    }
    assert!(payload_receiver.try_recv().is_err());
    assert!(available_receiver.try_recv().is_err());

    // Stage 2: import fires execution_payload and execution_payload_available.
    harness
        .chain
        .process_execution_payload_envelope(
            block_root,
            gossip_verified,
            beacon_chain::NotifyExecutionLayer::Yes,
            types::BlockImportSource::Gossip,
            #[allow(clippy::result_large_err)]
            || Ok(()),
        )
        .await
        .expect("envelope import should succeed");

    let payload_event = payload_receiver
        .try_recv()
        .expect("should receive execution_payload after import");
    if let EventKind::ExecutionPayload(sse) = payload_event {
        assert_eq!(sse.slot, target_slot);
        assert_eq!(sse.block_root, block_root);
    } else {
        panic!("Expected ExecutionPayload event, got {:?}", payload_event);
    }

    let available_event = available_receiver
        .try_recv()
        .expect("should receive execution_payload_available after import");
    if let EventKind::ExecutionPayloadAvailable(sse) = available_event {
        assert_eq!(sse.slot, target_slot);
        assert_eq!(sse.block_root, block_root);
    } else {
        panic!(
            "Expected ExecutionPayloadAvailable event, got {:?}",
            available_event
        );
    }

    assert!(
        gossip_receiver.try_recv().is_err(),
        "no extra gossip events should fire during import"
    );
}

/// Verifies that a `payload_attestation_message` event is emitted when a payload attestation
/// message passes gossip verification.
#[tokio::test]
async fn payload_attestation_message_event_on_gossip_verification() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // Advance chain to have a valid head block.
    let target_slot = Slot::new(1);
    harness.extend_to_slot(target_slot).await;

    let head = harness.chain.canonical_head.cached_head();
    let head_state = &head.snapshot.beacon_state;

    // Get a PTC member for this slot.
    let ptc = head_state
        .get_ptc(target_slot, &harness.spec)
        .expect("should get PTC");
    let validator_index = *ptc.0.first().expect("PTC should have at least one member") as u64;

    // Sign a payload attestation.
    let target_epoch = target_slot.epoch(E::slots_per_epoch());
    let domain = harness.spec.get_domain(
        target_epoch,
        Domain::PTCAttester,
        &head_state.fork(),
        head_state.genesis_validators_root(),
    );
    let data = PayloadAttestationData {
        beacon_block_root: head.head_block_root(),
        slot: target_slot,
        payload_present: true,
        blob_data_available: true,
    };
    let message = data.signing_root(domain);
    let signature = harness.validator_keypairs[validator_index as usize]
        .sk
        .sign(message);
    let msg = PayloadAttestationMessage {
        validator_index,
        data: data.clone(),
        signature: signature.clone(),
    };

    // Subscribe before verification.
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut receiver = event_handler.subscribe_payload_attestation_message();

    // Verify the attestation through the gossip path.
    harness
        .chain
        .verify_payload_attestation_message_for_gossip(msg)
        .expect("verification should succeed");

    // Assert the event was emitted.
    let event = receiver.try_recv().expect("should receive event");
    if let EventKind::PayloadAttestationMessage(versioned) = event {
        assert_eq!(versioned.data.validator_index, validator_index);
        assert_eq!(versioned.data.data, data);
    } else {
        panic!("Expected PayloadAttestationMessage event, got {:?}", event);
    }
}
