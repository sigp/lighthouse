use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::data_column_verification::GossipVerifiedDataColumn;
use beacon_chain::test_utils::{BeaconChainHarness, TEST_DATA_COLUMN_SIDECARS_SSZ};
use eth2::types::{EventKind, SseBlobSidecar, SseDataColumnSidecar};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::test_utils::TestRandom;
use types::{
    BlobSidecar, DataColumnSidecar, EthSpec, ForkName, MinimalEthSpec, RuntimeVariableList, Slot,
};

type E = MinimalEthSpec;

/// Verifies that a blob event is emitted when a gossip verified blob is received via gossip or the publish block API.
#[tokio::test]
async fn blob_sidecar_event_on_process_gossip_blob() {
    let spec = Arc::new(ForkName::Deneb.make_genesis_spec(E::default_spec()));
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
    let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
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
        // DA checker only accepts sampling columns, so we need to create one with a sampling index.
        let mut random_sidecar = DataColumnSidecar::random_for_test(&mut rng);
        let slot = Slot::new(10);
        let epoch = slot.epoch(E::slots_per_epoch());
        random_sidecar.signed_block_header.message.slot = slot;
        random_sidecar.index = harness.chain.sampling_columns_for_epoch(epoch)[0];
        random_sidecar
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
    let spec = Arc::new(ForkName::Deneb.make_genesis_spec(E::default_spec()));
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
    let kzg = harness.chain.kzg.as_ref();
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);

    let mut blob_1 = BlobSidecar::random_valid(&mut rng, kzg).unwrap();
    let mut blob_2 = BlobSidecar {
        index: 1,
        ..BlobSidecar::random_valid(&mut rng, kzg).unwrap()
    };
    let parent_root = harness.chain.head().head_block_root();
    blob_1.signed_block_header.message.parent_root = parent_root;
    blob_2.signed_block_header.message.parent_root = parent_root;
    let blob_1 = Arc::new(blob_1);
    let blob_2 = Arc::new(blob_2);

    let blobs = FixedBlobSidecarList::new(vec![Some(blob_1.clone()), Some(blob_2.clone())]);
    let expected_sse_blobs = vec![
        SseBlobSidecar::from_blob_sidecar(blob_1.as_ref()),
        SseBlobSidecar::from_blob_sidecar(blob_2.as_ref()),
    ];

    let _ = harness
        .chain
        .process_rpc_blobs(blob_1.slot(), blob_1.block_root(), blobs)
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
    let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // subscribe to blob sidecar events
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut data_column_event_receiver = event_handler.subscribe_data_column_sidecar();

    // load the precomputed column sidecar to avoid computing them for every block in the tests.
    let mut sidecar = RuntimeVariableList::<DataColumnSidecar<E>>::from_ssz_bytes(
        TEST_DATA_COLUMN_SIDECARS_SSZ,
        spec.number_of_columns as usize,
    )
    .unwrap()[0]
        .clone();
    let parent_root = harness.chain.head().head_block_root();
    sidecar.signed_block_header.message.parent_root = parent_root;
    let expected_sse_data_column = SseDataColumnSidecar::from_data_column_sidecar(&sidecar);

    let _ = harness
        .chain
        .process_rpc_custody_columns(vec![Arc::new(sidecar)])
        .await
        .unwrap();

    let sidecar_event = data_column_event_receiver.try_recv().unwrap();
    assert_eq!(
        sidecar_event,
        EventKind::DataColumnSidecar(expected_sse_data_column)
    );
}
