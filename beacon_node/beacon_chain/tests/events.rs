use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::test_utils::BeaconChainHarness;
use bls::Signature;
use eth2::types::EventKind;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BlobSidecar, EthSpec, ForkName, MinimalEthSpec, SignedBlobSidecar};

type E = MinimalEthSpec;

/// This covers scenarios for gossip verified blobs received via gossip or the published block API.  
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

// TODO: emit an event when rpc blob processed?
// async fn blob_sidecar_event_when_rpc_blob_processed() {}
