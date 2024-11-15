use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::test_utils::BeaconChainHarness;
use eth2::types::{EventKind, SseBlobSidecar};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, ForkName, MinimalEthSpec};

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

    let blobs = FixedBlobSidecarList::from(vec![Some(blob_1.clone()), Some(blob_2.clone())]);
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
