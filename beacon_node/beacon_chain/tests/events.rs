use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::test_utils::BeaconChainHarness;
use bls::Signature;
use eth2::types::EventKind;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::marker::PhantomData;
use std::sync::Arc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, ForkName, MinimalEthSpec, SignedBlobSidecar};

type E = MinimalEthSpec;

/// Verifies that a blob event is emitted when a gossip verified blob is received via gossip or the publish block API.  
#[tokio::test]
async fn blob_sidecar_event_on_process_gossip_blob() {
    let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
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
    let kzg = harness.chain.kzg.as_ref().unwrap();
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
    let signed_sidecar = SignedBlobSidecar {
        message: BlobSidecar::random_valid(&mut rng, kzg)
            .map(Arc::new)
            .unwrap(),
        signature: Signature::empty(),
        _phantom: PhantomData,
    };
    let gossip_verified_blob = GossipVerifiedBlob::__assumed_valid(signed_sidecar);
    let _ = harness
        .chain
        .process_gossip_blob(gossip_verified_blob)
        .await
        .unwrap();

    let sidecar_event = blob_event_receiver.try_recv().unwrap();
    assert!(matches!(sidecar_event, EventKind::BlobSidecar(..)));
}

/// Verifies that a blob event is emitted when blobs are received via RPC.  
#[tokio::test]
async fn blob_sidecar_event_on_process_rpc_blobs() {
    let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
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
    let kzg = harness.chain.kzg.as_ref().unwrap();
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);

    let blob_1 = BlobSidecar::random_valid(&mut rng, kzg)
        .map(Arc::new)
        .unwrap();
    let blob_2 = Arc::new(BlobSidecar {
        index: 1,
        ..BlobSidecar::random_valid(&mut rng, kzg).unwrap()
    });
    let blobs = FixedBlobSidecarList::from(vec![Some(blob_1.clone()), Some(blob_2)]);

    let _ = harness
        .chain
        .process_rpc_blobs(blob_1.slot, blob_1.block_root, blobs)
        .await
        .unwrap();

    let mut events: Vec<EventKind<E>> = vec![];
    while let Ok(sidecar_event) = blob_event_receiver.try_recv() {
        assert!(matches!(sidecar_event, EventKind::BlobSidecar(..)));
        events.push(sidecar_event);
    }
    assert!(events.len() == 2);
}
