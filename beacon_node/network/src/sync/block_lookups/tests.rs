#![cfg(feature = "spec-minimal")]
use std::sync::Arc;

use crate::service::RequestId;
use crate::sync::manager::RequestId as SyncId;
use crate::NetworkMessage;

use super::*;

use beacon_chain::{
    builder::Witness,
    eth1_chain::CachingEth1Backend,
    test_utils::{build_log, BeaconChainHarness, EphemeralHarnessType},
};
use execution_layer::BlobsBundleV1;
pub use genesis::{interop_genesis_state, DEFAULT_ETH1_BLOCK_HASH};
use lighthouse_network::rpc::RPCResponseErrorCode;
use lighthouse_network::{NetworkGlobals, Request};
use slot_clock::TestingSlotClock;
use std::time::Duration;
use store::MemoryStore;
use tokio::sync::mpsc;
use types::{
    map_fork_name, map_fork_name_with,
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
    BeaconBlock, EthSpec, ForkName, FullPayloadDeneb, MinimalEthSpec as E, SignedBeaconBlock,
};

type T = Witness<TestingSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

struct TestRig {
    beacon_processor_rx: mpsc::Receiver<WorkEvent<T>>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    rng: XorShiftRng,
    harness: BeaconChainHarness<T>,
}

const D: Duration = Duration::new(0, 0);

enum NumBlobs {
    Random,
    None,
}

impl TestRig {
    fn test_setup(enable_log: bool) -> (BlockLookups<T>, SyncNetworkContext<T>, Self) {
        let log = build_log(slog::Level::Debug, enable_log);

        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .default_spec()
            .logger(log.clone())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .build();

        let chain = harness.chain.clone();

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(100);
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let rng = XorShiftRng::from_seed([42; 16]);
        let rig = TestRig {
            beacon_processor_rx,
            network_rx,
            rng,
            harness,
        };

        let bl = BlockLookups::new(
            chain.data_availability_checker.clone(),
            log.new(slog::o!("component" => "block_lookups")),
        );
        let cx = {
            let globals = Arc::new(NetworkGlobals::new_test_globals(&log));
            SyncNetworkContext::new(
                network_tx,
                globals,
                beacon_processor_tx,
                chain,
                log.new(slog::o!("component" => "network_context")),
            )
        };

        (bl, cx, rig)
    }

    fn rand_block(&mut self, fork_name: ForkName) -> SignedBeaconBlock<E> {
        self.rand_block_and_blobs(fork_name, NumBlobs::None).0
    }

    fn rand_block_and_blobs(
        &mut self,
        fork_name: ForkName,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let inner = map_fork_name!(fork_name, BeaconBlock, <_>::random_for_test(&mut self.rng));
        let mut block =
            SignedBeaconBlock::from_block(inner, types::Signature::random_for_test(&mut self.rng));
        let mut blob_sidecars = vec![];
        if let Ok(message) = block.message_deneb_mut() {
            // get random number between 0 and Max Blobs
            let mut payload: &mut FullPayloadDeneb<E> = &mut message.body.execution_payload;
            let num_blobs = match num_blobs {
                NumBlobs::Random => {
                    let mut num_blobs = rand::random::<usize>() % E::max_blobs_per_block();
                    if num_blobs == 0 {
                        num_blobs += 1;
                    }
                    num_blobs
                }
                NumBlobs::None => 0,
            };
            let (bundle, transactions) = execution_layer::test_utils::generate_random_blobs::<E>(
                num_blobs,
                &self.harness.chain.kzg.as_ref().unwrap(),
            )
            .unwrap();
            //TODO(sean) maybe we want to keep other random txs ?
            payload.execution_payload.transactions = <_>::default();
            for tx in Vec::from(transactions) {
                payload.execution_payload.transactions.push(tx).unwrap();
            }
            message.body.blob_kzg_commitments = bundle.commitments.clone();

            let BlobsBundleV1 {
                commitments,
                proofs,
                blobs,
            } = bundle;

            let block_root = block.canonical_root();

            for (index, ((blob, kzg_commitment), kzg_proof)) in blobs
                .into_iter()
                .zip(commitments.into_iter())
                .zip(proofs.into_iter())
                .enumerate()
            {
                blob_sidecars.push(BlobSidecar {
                    block_root,
                    index: index as u64,
                    slot: block.slot(),
                    block_parent_root: block.parent_root(),
                    proposer_index: block.message().proposer_index(),
                    blob: blob.clone(),
                    kzg_commitment: kzg_commitment.clone(),
                    kzg_proof: kzg_proof.clone(),
                });
            }
        }

        (block, blob_sidecars)
    }

    #[track_caller]
    fn expect_block_request(&mut self, response_type: ResponseType) -> Id {
        match response_type {
            ResponseType::Block => match self.network_rx.try_recv() {
                Ok(NetworkMessage::SendRequest {
                    peer_id: _,
                    request: Request::BlocksByRoot(_request),
                    request_id: RequestId::Sync(SyncId::SingleBlock { id }),
                }) => id,
                other => {
                    panic!("Expected block request, found {:?}", other);
                }
            },
            ResponseType::Blob => match self.network_rx.try_recv() {
                Ok(NetworkMessage::SendRequest {
                    peer_id: _,
                    request: Request::BlobsByRoot(_request),
                    request_id: RequestId::Sync(SyncId::SingleBlock { id }),
                }) => id,
                other => {
                    panic!("Expected blob request, found {:?}", other);
                }
            },
        }
    }

    #[track_caller]
    fn expect_parent_request(&mut self, response_type: ResponseType) -> Id {
        match response_type {
            ResponseType::Block => match self.network_rx.try_recv() {
                Ok(NetworkMessage::SendRequest {
                    peer_id: _,
                    request: Request::BlocksByRoot(_request),
                    request_id: RequestId::Sync(SyncId::ParentLookup { id }),
                }) => id,
                other => panic!("Expected parent request, found {:?}", other),
            },
            ResponseType::Blob => match self.network_rx.try_recv() {
                Ok(NetworkMessage::SendRequest {
                    peer_id: _,
                    request: Request::BlobsByRoot(_request),
                    request_id: RequestId::Sync(SyncId::ParentLookup { id }),
                }) => id,
                other => panic!("Expected parent blobs request, found {:?}", other),
            },
        }
    }

    #[track_caller]
    fn expect_block_process(&mut self, response_type: ResponseType) {
        match response_type {
            ResponseType::Block => match self.beacon_processor_rx.try_recv() {
                Ok(work) => {
                    assert_eq!(work.work_type(), crate::beacon_processor::RPC_BLOCK);
                }
                other => panic!("Expected block process, found {:?}", other),
            },
            ResponseType::Blob => match self.beacon_processor_rx.try_recv() {
                Ok(work) => {
                    assert_eq!(work.work_type(), crate::beacon_processor::RPC_BLOB);
                }
                other => panic!("Expected blob process, found {:?}", other),
            },
        }
    }

    #[track_caller]
    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                assert_eq!(work.work_type(), crate::beacon_processor::CHAIN_SEGMENT);
            }
            other => panic!("Expected chain segment process, found {:?}", other),
        }
    }

    #[track_caller]
    fn expect_empty_network(&mut self) {
        assert_eq!(
            self.network_rx.try_recv().expect_err("must err"),
            mpsc::error::TryRecvError::Empty
        );
    }

    #[track_caller]
    pub fn expect_penalty(&mut self) {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::ReportPeer { .. }) => {}
            other => panic!("Expected peer penalty, found {:?}", other),
        }
    }

    pub fn block_with_parent(
        &mut self,
        parent_root: Hash256,
        fork_name: ForkName,
    ) -> SignedBeaconBlock<E> {
        let mut block = self.rand_block(fork_name);
        *block.message_mut().parent_root_mut() = parent_root;
        block
    }
}

#[test]
fn test_single_block_lookup_happy_path() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let block = rig.rand_block(fork_name);
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    // Trigger the request
    bl.search_block(block_root, PeerSource::Attestation(peer_id), &mut cx);
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.into()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    bl.single_block_processed(
        id,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        response_type,
        &mut cx,
    );
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_single_block_lookup_empty_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, PeerSource::Attestation(peer_id), &mut cx);
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // The peer does not have the block. It should be penalized.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    rig.expect_penalty();

    rig.expect_block_request(response_type); // it should be retried
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, PeerSource::Attestation(peer_id), &mut cx);
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // Peer sends something else. It should be penalized.
    let bad_block = rig.rand_block(fork_name);
    bl.single_block_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
    rig.expect_penalty();
    rig.expect_block_request(response_type); // should be retried

    // Send the stream termination. This should not produce an additional penalty.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_failure() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, PeerSource::Attestation(peer_id), &mut cx);
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    bl.single_block_lookup_failed(id, &peer_id, &mut cx, RPCError::UnsupportedProtocol);
    rig.expect_block_request(response_type);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_becomes_parent_request() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block = Arc::new(rig.rand_block(fork_name));
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(
        block.canonical_root(),
        PeerSource::Attestation(peer_id),
        &mut cx,
    );
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.clone()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request moved to a
    // parent request after processing.
    bl.single_block_processed(
        id,
        BlockError::ParentUnknown(block.into()).into(),
        response_type,
        &mut cx,
    );
    assert_eq!(bl.single_block_lookups.len(), 1);
    rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 1);
}

#[test]
fn test_parent_lookup_happy_path() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    let id = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockError::BlockIsAlreadyKnown.into(),
        response_type,
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_wrong_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the wrong block, peer should be penalized and the block re-requested.
    let bad_block = rig.rand_block(fork_name);
    bl.parent_lookup_response(id1, peer_id, Some(bad_block.into()), D, &mut cx);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the stream termination for the first request. This should not produce extra penalties.
    bl.parent_lookup_response(id1, peer_id, None, D, &mut cx);
    rig.expect_empty_network();

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        response_type,
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_empty_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends an empty response, peer should be penalized and the block re-requested.
    bl.parent_lookup_response(id1, peer_id, None, D, &mut cx);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        response_type,
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_rpc_failure() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // The request fails. It should be tried again.
    bl.parent_lookup_failed(
        id1,
        peer_id,
        &mut cx,
        RPCError::ErrorResponse(
            RPCResponseErrorCode::ResourceUnavailable,
            "older than deneb".into(),
        ),
    );
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        response_type,
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_many_attempts() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb) && i == 1 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        match i % 2 {
            // make sure every error is accounted for
            0 => {
                // The request fails. It should be tried again.
                bl.parent_lookup_failed(
                    id,
                    peer_id,
                    &mut cx,
                    RPCError::ErrorResponse(
                        RPCResponseErrorCode::ResourceUnavailable,
                        "older than deneb".into(),
                    ),
                );
            }
            _ => {
                // Send a bad block this time. It should be tried again.
                let bad_block = rig.rand_block(fork_name);
                bl.parent_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
                // Send the stream termination
                bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
                rig.expect_penalty();
            }
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(bl.parent_lookups[0].failed_block_attempts(), dbg!(i));
        }
    }

    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_many_download_attempts_no_blacklist() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let block_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        assert!(!bl.failed_chains.contains(&block_hash));
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb) && i == 1 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        if i % 2 != 0 {
            // The request fails. It should be tried again.
            bl.parent_lookup_failed(
                id,
                peer_id,
                &mut cx,
                RPCError::ErrorResponse(
                    RPCResponseErrorCode::ResourceUnavailable,
                    "older than deneb".into(),
                ),
            );
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block(fork_name);
            bl.parent_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
            rig.expect_penalty();
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(bl.parent_lookups[0].failed_block_attempts(), dbg!(i));
        }
    }

    assert_eq!(bl.parent_lookups.len(), 0);
    assert!(!bl.failed_chains.contains(&block_hash));
    assert!(!bl.failed_chains.contains(&parent.canonical_root()));
}

#[test]
fn test_parent_lookup_too_many_processing_attempts_must_blacklist() {
    let response_type = ResponseType::Block;
    const PROCESSING_FAILURES: u8 = parent_lookup::PARENT_FAIL_TOLERANCE / 2 + 1;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let parent = Arc::new(rig.rand_block(fork_name));
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);

    // Fail downloading the block
    for i in 0..(parent_lookup::PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb) && i == 0 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // The request fails. It should be tried again.
        bl.parent_lookup_failed(
            id,
            peer_id,
            &mut cx,
            RPCError::ErrorResponse(
                RPCResponseErrorCode::ResourceUnavailable,
                "older than deneb".into(),
            ),
        );
    }

    // Now fail processing a block in the parent request
    for _ in 0..PROCESSING_FAILURES {
        let id = dbg!(rig.expect_parent_request(response_type));
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        assert!(!bl.failed_chains.contains(&block_root));
        // send the right parent but fail processing
        bl.parent_lookup_response(id, peer_id, Some(parent.clone()), D, &mut cx);
        bl.parent_block_processed(
            block_root,
            BlockError::InvalidSignature.into(),
            response_type,
            &mut cx,
        );
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        rig.expect_penalty();
    }

    assert!(bl.failed_chains.contains(&block_root));
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_deep() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let mut blocks =
        Vec::<Arc<SignedBeaconBlock<E>>>::with_capacity(parent_lookup::PARENT_DEPTH_TOLERANCE);
    while blocks.len() < parent_lookup::PARENT_DEPTH_TOLERANCE {
        let parent = blocks
            .last()
            .map(|b| b.canonical_root())
            .unwrap_or_else(Hash256::random);
        let block = Arc::new(rig.block_with_parent(parent, fork_name));
        blocks.push(block);
    }

    let peer_id = PeerId::random();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    let trigger_block_root = trigger_block.canonical_root();
    let trigger_parent_root = trigger_block.parent_root();
    let trigger_slot = trigger_block.slot();
    bl.search_parent(
        trigger_slot,
        trigger_block_root,
        trigger_parent_root,
        peer_id,
        &mut cx,
    );

    for block in blocks.into_iter().rev() {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb) {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // the block
        bl.parent_lookup_response(id, peer_id, Some(block.clone()), D, &mut cx);
        // the stream termination
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        bl.parent_block_processed(
            chain_hash,
            BlockError::ParentUnknown(block.into()).into(),
            response_type,
            &mut cx,
        )
    }

    rig.expect_penalty();
    assert!(bl.failed_chains.contains(&chain_hash));
}

#[test]
fn test_parent_lookup_disconnection() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let peer_id = PeerId::random();
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let trigger_block = rig.rand_block(fork_name);
    let trigger_block_root = trigger_block.canonical_root();
    let trigger_parent_root = trigger_block.parent_root();
    let trigger_slot = trigger_block.slot();
    bl.search_parent(
        trigger_slot,
        trigger_block_root,
        trigger_parent_root,
        peer_id,
        &mut cx,
    );

    bl.peer_disconnected(&peer_id, &mut cx);
    assert!(bl.parent_lookups.is_empty());
}

#[test]
fn test_single_block_lookup_ignored_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block = rig.rand_block(fork_name);
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(
        block.canonical_root(),
        PeerSource::Attestation(peer_id),
        &mut cx,
    );
    let id = rig.expect_block_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_block_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.into()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    // Send an Ignored response, the request should be dropped
    bl.single_block_processed(id, BlockProcessingResult::Ignored, response_type, &mut cx);
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_ignored_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
    let id = rig.expect_parent_request(response_type);

    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ignored,
        response_type,
        &mut cx,
    );
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 0);
}

/// This is a regression test.
#[test]
fn test_same_chain_race_condition() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(true);

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    #[track_caller]
    fn parent_lookups_consistency(bl: &BlockLookups<T>) {
        let hashes: Vec<_> = bl
            .parent_lookups
            .iter()
            .map(|req| req.chain_hash())
            .collect();
        let expected = hashes.len();
        assert_eq!(
            expected,
            hashes
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "duplicated chain hashes in parent queue"
        )
    }
    // if we use one or two blocks it will match on the hash or the parent hash, so make a longer
    // chain.
    let depth = 4;
    let mut blocks = Vec::<Arc<SignedBeaconBlock<E>>>::with_capacity(depth);
    while blocks.len() < depth {
        let parent = blocks
            .last()
            .map(|b| b.canonical_root())
            .unwrap_or_else(Hash256::random);
        let block = Arc::new(rig.block_with_parent(parent, fork_name));
        blocks.push(block);
    }

    let peer_id = PeerId::random();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    let trigger_block_root = trigger_block.canonical_root();
    let trigger_parent_root = trigger_block.parent_root();
    let trigger_slot = trigger_block.slot();
    bl.search_parent(
        trigger_slot,
        trigger_block_root,
        trigger_parent_root,
        peer_id,
        &mut cx,
    );

    for (i, block) in blocks.into_iter().rev().enumerate() {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb) {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // the block
        bl.parent_lookup_response(id, peer_id, Some(block.clone()), D, &mut cx);
        // the stream termination
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        if i + 2 == depth {
            // one block was removed
            bl.parent_block_processed(
                chain_hash,
                BlockError::BlockIsAlreadyKnown.into(),
                response_type,
                &mut cx,
            )
        } else {
            bl.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(block.into()).into(),
                response_type,
                &mut cx,
            )
        }
        parent_lookups_consistency(&bl)
    }

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.expect_parent_chain_process();

    // Try to get this block again while the chain is being processed. We should not request it again.
    let peer_id = PeerId::random();
    let trigger_block_root = trigger_block.canonical_root();
    let trigger_parent_root = trigger_block.parent_root();
    let trigger_slot = trigger_block.slot();
    bl.search_parent(
        trigger_slot,
        trigger_block_root,
        trigger_parent_root,
        peer_id,
        &mut cx,
    );
    parent_lookups_consistency(&bl);

    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

mod deneb_only {
    use super::*;
    use std::str::FromStr;

    fn get_fork_name() -> ForkName {
        ForkName::from_str(
            &std::env::var(beacon_chain::test_utils::FORK_NAME_ENV_VAR).unwrap_or_else(|e| {
                panic!(
                    "{} env var must be defined when using fork_from_env: {:?}",
                    beacon_chain::test_utils::FORK_NAME_ENV_VAR,
                    e
                )
            }),
        )
        .unwrap()
    }

    #[test]
    fn single_block_and_blob_lookup_block_returned_first() {
        let fork_name = get_fork_name();
        if !matches!(fork_name, ForkName::Deneb) {
            return;
        }
        let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
        rig.harness
            .chain
            .slot_clock
            .set_slot(E::slots_per_epoch() * rig.harness.spec.deneb_fork_epoch.unwrap().as_u64());

        let (block, blobs) = rig.rand_block_and_blobs(fork_name, NumBlobs::Random);
        let slot = block.slot();
        let peer_id = PeerId::random();
        let block_root = block.canonical_root();

        // Trigger the request
        bl.search_block(block_root, PeerSource::Attestation(peer_id), &mut cx);
        let block_id = rig.expect_block_request(ResponseType::Block);
        let blob_id = rig.expect_block_request(ResponseType::Blob);

        // The peer provides the correct block, should not be penalized. Now the block should be sent
        // for processing.
        bl.single_block_lookup_response(block_id, peer_id, Some(block.into()), D, &mut cx);
        rig.expect_empty_network();
        rig.expect_block_process(ResponseType::Block);

        // The request should still be active.
        assert_eq!(bl.single_block_lookups.len(), 1);

        // Send the stream termination. Peer should have not been penalized.
        bl.single_block_lookup_response(block_id, peer_id, None, D, &mut cx);
        // Missing blobs should be the request is not removed, the outstanding blobs request should
        // mean we do not send a new request.
        bl.single_block_processed(
            block_id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                slot, block_root,
            )),
            ResponseType::Block,
            &mut cx,
        );
        rig.expect_empty_network();
        assert_eq!(bl.single_block_lookups.len(), 1);

        for blob in blobs {
            bl.single_blob_lookup_response(blob_id, peer_id, Some(Arc::new(blob)), D, &mut cx);
            rig.expect_empty_network();
            assert_eq!(bl.single_block_lookups.len(), 1);
        }
        // Send the blob stream termination. Peer should have not been penalized.
        bl.single_blob_lookup_response(blob_id, peer_id, None, D, &mut cx);
        rig.expect_empty_network();
        rig.expect_block_process(ResponseType::Blob);

        // Missing blobs should be the request is not removed, the outstanding blobs request should
        // mean we do not send a new request.
        bl.single_block_processed(
            block_id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
            ResponseType::Block,
            &mut cx,
        );
        rig.expect_empty_network();
        assert_eq!(bl.single_block_lookups.len(), 0);
    }

    #[test]
    fn single_block_and_blob_lookup_blob_returned_first() {
        let fork_name = get_fork_name();
        if !matches!(fork_name, ForkName::Deneb) {
            return;
        }
        let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
        rig.harness
            .chain
            .slot_clock
            .set_slot(E::slots_per_epoch() * rig.harness.spec.deneb_fork_epoch.unwrap().as_u64());

        let (block, blobs) = rig.rand_block_and_blobs(fork_name, NumBlobs::Random);
        let slot = block.slot();
        let peer_id = PeerId::random();
        let block_root = block.canonical_root();

        // Trigger the request
        bl.search_block(block_root, PeerSource::Attestation(peer_id), &mut cx);
        let block_id = rig.expect_block_request(ResponseType::Block);
        let blob_id = rig.expect_block_request(ResponseType::Blob);

        for blob in blobs {
            bl.single_blob_lookup_response(blob_id, peer_id, Some(Arc::new(blob)), D, &mut cx);
            rig.expect_empty_network();
            assert_eq!(bl.single_block_lookups.len(), 1);
        }
        // Send the blob stream termination. Peer should have not been penalized.
        bl.single_blob_lookup_response(blob_id, peer_id, None, D, &mut cx);
        rig.expect_empty_network();
        rig.expect_block_process(ResponseType::Blob);

        // The request should still be active.
        assert_eq!(bl.single_block_lookups.len(), 1);

        // The peer provides the correct block, should not be penalized. Now the block should be sent
        // for processing.
        bl.single_block_lookup_response(block_id, peer_id, Some(block.into()), D, &mut cx);
        rig.expect_empty_network();
        rig.expect_block_process(ResponseType::Block);

        // Send the stream termination. Peer should have not been penalized.
        bl.single_block_lookup_response(block_id, peer_id, None, D, &mut cx);
        // Missing blobs should be the request is not removed, the outstanding blobs request should
        // mean we do not send a new request.
        bl.single_block_processed(
            block_id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                slot, block_root,
            )),
            ResponseType::Block,
            &mut cx,
        );
        rig.expect_empty_network();
        assert_eq!(bl.single_block_lookups.len(), 1);

        // Missing blobs should be the request is not removed, the outstanding blobs request should
        // mean we do not send a new request.
        bl.single_block_processed(
            block_id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
            ResponseType::Block,
            &mut cx,
        );
        rig.expect_empty_network();
        assert_eq!(bl.single_block_lookups.len(), 0);
    }

    #[test]
    fn single_block_and_blob_lookup_empty_response() {
        let response_type = ResponseType::Block;
        let fork_name = get_fork_name();
        if !matches!(fork_name, ForkName::Deneb) {
            return;
        }
        let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

        let block_hash = Hash256::random();
        let peer_id = PeerId::random();

        // Trigger the request
        bl.search_block(block_hash, PeerSource::Attestation(peer_id), &mut cx);
        let id = rig.expect_block_request(response_type);
        let blob_id = rig.expect_block_request(ResponseType::Blob);

        // The peer does not have the block. It should be penalized.
        bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
        rig.expect_penalty();

        rig.expect_block_request(response_type); // it should be retried
        rig.expect_empty_network(); // there should be no blob retry

        bl.single_blob_lookup_response(blob_id, peer_id, None, D, &mut cx);
        rig.expect_empty_network(); // there should be no penalty or retry, we don't know
                                    // whether we should have blobs
    }

    #[test]
    fn single_blob_lookup_empty_response() {
        let response_type = ResponseType::Block;
        let fork_name = get_fork_name();
        if !matches!(fork_name, ForkName::Deneb) {
            return;
        }
        let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

        let block_hash = Hash256::random();
        let peer_id = PeerId::random();

        // Trigger the request
        bl.search_block(block_hash, PeerSource::Attestation(peer_id), &mut cx);
        let id = rig.expect_block_request(response_type);
        let _ = rig.expect_block_request(ResponseType::Blob);

        // The peer does not have the block. It should be penalized.
        bl.single_blob_lookup_response(id, peer_id, None, D, &mut cx);
        rig.expect_empty_network(); // there should be no penalty or retry, we don't know
                                    // whether we should have blobs
    }

    #[test]
    fn test_single_block_response_then_empty_blob_response() {
        let fork_name = get_fork_name();
        if !matches!(fork_name, ForkName::Deneb) {
            return;
        }
        let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
        rig.harness
            .chain
            .slot_clock
            .set_slot(E::slots_per_epoch() * rig.harness.spec.deneb_fork_epoch.unwrap().as_u64());

        let (block, _) = rig.rand_block_and_blobs(fork_name, NumBlobs::Random);
        let slot = block.slot();
        let peer_id = PeerId::random();
        let block_root = block.canonical_root();

        // Trigger the request
        bl.search_block(block_root, PeerSource::Attestation(peer_id), &mut cx);
        let block_id = rig.expect_block_request(ResponseType::Block);
        let blob_id = rig.expect_block_request(ResponseType::Blob);

        // The peer provides the correct block, should not be penalized. Now the block should be sent
        // for processing.
        bl.single_block_lookup_response(block_id, peer_id, Some(block.into()), D, &mut cx);
        rig.expect_empty_network();
        rig.expect_block_process(ResponseType::Block);

        // The request should still be active.
        assert_eq!(bl.single_block_lookups.len(), 1);

        // Send the stream termination. Peer should have not been penalized.
        bl.single_block_lookup_response(block_id, peer_id, None, D, &mut cx);
        // Missing blobs should be the request is not removed, the outstanding blobs request should
        // mean we do not send a new request.
        bl.single_block_processed(
            block_id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                slot, block_root,
            )),
            ResponseType::Block,
            &mut cx,
        );
        rig.expect_empty_network();
        assert_eq!(bl.single_block_lookups.len(), 1);

        // The peer does not have the block. It should be penalized.
        bl.single_blob_lookup_response(blob_id, peer_id, None, D, &mut cx);
        rig.expect_penalty();

        rig.expect_block_request(ResponseType::Blob); // it should be retried
        rig.expect_empty_network();
    }
}
