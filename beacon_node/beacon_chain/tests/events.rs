use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::data_column_verification::GossipVerifiedDataColumn;
use beacon_chain::test_utils::{
    BeaconChainHarness, fork_name_from_env, generate_data_column_sidecars_from_block, test_spec,
};
use eth2::types::{EventKind, SseBlobSidecar, SseDataColumnSidecar};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;
use types::data::FixedBlobSidecarList;
use types::test_utils::TestRandom;
use types::{
    BlobSidecar, DataColumnSidecar, DataColumnSidecarFulu, DataColumnSidecarGloas, EthSpec,
    MinimalEthSpec, Slot,
};

type E = MinimalEthSpec;

/// Verifies that a blob event is emitted when a gossip verified blob is received via gossip or the publish block API.
#[tokio::test]
async fn blob_sidecar_event_on_process_gossip_blob() {
    if fork_name_from_env().is_some_and(|f| !f.deneb_enabled() || f.fulu_enabled()) {
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

    // build and process a gossip verified blob
    let kzg = harness.chain.kzg.as_ref();
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
    let sidecar = BlobSidecar::random_valid(&mut rng, kzg)
        .map(Arc::new)
        .unwrap();
    let gossip_verified_blob = GossipVerifiedBlob::__assumed_valid(sidecar);
    let expected_sse_blobs = SseBlobSidecar::from_blob_sidecar(gossip_verified_blob.as_blob());

    let _ = harness
        .chain
        .process_gossip_blob(gossip_verified_blob)
        .await
        .unwrap();

    let sidecar_event = blob_event_receiver.try_recv().unwrap();
    assert_eq!(sidecar_event, EventKind::BlobSidecar(expected_sse_blobs));
}

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
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
    let sidecar = {
        let slot = Slot::new(10);
        let fork_name = harness.spec.fork_name_at_slot::<E>(slot);
        // DA checker only accepts sampling columns, so we need to create one with a sampling index.
        if fork_name.gloas_enabled() {
            let mut random_sidecar = DataColumnSidecarGloas::random_for_test(&mut rng);
            let epoch = slot.epoch(E::slots_per_epoch());
            random_sidecar.slot = slot;
            random_sidecar.index = harness.chain.sampling_columns_for_epoch(epoch)[0];
            DataColumnSidecar::Gloas(random_sidecar)
        } else {
            let mut random_sidecar = DataColumnSidecarFulu::random_for_test(&mut rng);
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
    if fork_name_from_env().is_some_and(|f| !f.deneb_enabled() || f.fulu_enabled()) {
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
    if fork_name_from_env().is_some_and(|f| !f.fulu_enabled()) {
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
