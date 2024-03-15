use crate::network_beacon_processor::NetworkBeaconProcessor;

use crate::service::RequestId;
use crate::sync::manager::{RequestId as SyncId, SingleLookupReqId};
use crate::NetworkMessage;
use std::sync::Arc;

use super::*;

use crate::sync::block_lookups::common::ResponseType;
use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::{
    build_log, generate_rand_block_and_blobs, BeaconChainHarness, EphemeralHarnessType, NumBlobs,
};
use beacon_processor::WorkEvent;
use lighthouse_network::rpc::RPCResponseErrorCode;
use lighthouse_network::{NetworkGlobals, Request};
use slot_clock::{ManualSlotClock, SlotClock, TestingSlotClock};
use store::MemoryStore;
use tokio::sync::mpsc;
use types::{
    test_utils::{SeedableRng, XorShiftRng},
    BlobSidecar, EthSpec, ForkName, MinimalEthSpec as E, SignedBeaconBlock,
};

type T = Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

struct TestRig {
    beacon_processor_rx: mpsc::Receiver<WorkEvent<E>>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    rng: XorShiftRng,
    harness: BeaconChainHarness<T>,
}

const D: Duration = Duration::new(0, 0);

impl TestRig {
    fn test_setup(enable_log: bool) -> (BlockLookups<T>, SyncNetworkContext<T>, Self) {
        let log = build_log(slog::Level::Debug, enable_log);

        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .default_spec()
            .logger(log.clone())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .testing_slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(0),
                Duration::from_secs(12),
            ))
            .build();

        let chain = harness.chain.clone();

        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let globals = Arc::new(NetworkGlobals::new_test_globals(Vec::new(), &log));
        let (network_beacon_processor, beacon_processor_rx) =
            NetworkBeaconProcessor::null_for_testing(globals);
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
            SyncNetworkContext::new(
                network_tx,
                Arc::new(network_beacon_processor),
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
        let rng = &mut self.rng;
        generate_rand_block_and_blobs::<E>(fork_name, num_blobs, rng)
    }

    #[track_caller]
    fn expect_lookup_request(&mut self, response_type: ResponseType) -> SingleLookupReqId {
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
                    request_id: RequestId::Sync(SyncId::SingleBlob { id }),
                }) => id,
                other => {
                    panic!("Expected blob request, found {:?}", other);
                }
            },
        }
    }

    #[track_caller]
    fn expect_parent_request(&mut self, response_type: ResponseType) -> SingleLookupReqId {
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
                    request_id: RequestId::Sync(SyncId::ParentLookupBlob { id }),
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
                    assert_eq!(work.work_type(), beacon_processor::RPC_BLOCK);
                }
                other => panic!("Expected block process, found {:?}", other),
            },
            ResponseType::Blob => match self.beacon_processor_rx.try_recv() {
                Ok(work) => {
                    assert_eq!(work.work_type(), beacon_processor::RPC_BLOBS);
                }
                other => panic!("Expected blob process, found {:?}", other),
            },
        }
    }

    #[track_caller]
    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                assert_eq!(work.work_type(), beacon_processor::CHAIN_SEGMENT);
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
    fn expect_empty_beacon_processor(&mut self) {
        assert_eq!(
            self.beacon_processor_rx.try_recv().expect_err("must err"),
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

    pub fn block_with_parent_and_blobs(
        &mut self,
        parent_root: Hash256,
        fork_name: ForkName,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let (mut block, mut blobs) = self.rand_block_and_blobs(fork_name, num_blobs);
        *block.message_mut().parent_root_mut() = parent_root;
        blobs.iter_mut().for_each(|blob| {
            blob.signed_block_header = block.signed_block_header();
        });
        (block, blobs)
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
    bl.search_block(block_root, &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_lookup_response::<BlockRequestState<Current>>(
        id,
        peer_id,
        Some(block.into()),
        D,
        &cx,
    );
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_lookup_response::<BlockRequestState<Current>>(id, peer_id, None, D, &cx);
    bl.single_block_component_processed::<BlockRequestState<Current>>(
        id.id,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
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
    bl.search_block(block_hash, &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer does not have the block. It should be penalized.
    bl.single_lookup_response::<BlockRequestState<Current>>(id, peer_id, None, D, &cx);
    rig.expect_penalty();

    rig.expect_lookup_request(response_type); // it should be retried
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
    bl.search_block(block_hash, &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // Peer sends something else. It should be penalized.
    let bad_block = rig.rand_block(fork_name);
    bl.single_lookup_response::<BlockRequestState<Current>>(
        id,
        peer_id,
        Some(bad_block.into()),
        D,
        &cx,
    );
    rig.expect_penalty();
    rig.expect_lookup_request(response_type); // should be retried

    // Send the stream termination. This should not produce an additional penalty.
    bl.single_lookup_response::<BlockRequestState<Current>>(id, peer_id, None, D, &cx);
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
    bl.search_block(block_hash, &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    bl.single_block_lookup_failed::<BlockRequestState<Current>>(
        id,
        &peer_id,
        &cx,
        RPCError::UnsupportedProtocol,
    );
    rig.expect_lookup_request(response_type);
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
    bl.search_block(block.canonical_root(), &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_lookup_response::<BlockRequestState<Current>>(
        id,
        peer_id,
        Some(block.clone()),
        D,
        &cx,
    );
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request moved to a
    // parent request after processing.
    bl.single_block_component_processed::<BlockRequestState<Current>>(
        id.id,
        BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
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
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id,
        peer_id,
        Some(parent.into()),
        D,
        &cx,
    );
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(chain_hash, BlockError::BlockIsAlreadyKnown.into(), &mut cx);
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &cx);
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
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id1,
        peer_id,
        Some(bad_block.into()),
        D,
        &cx,
    );
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the stream termination for the first request. This should not produce extra penalties.
    bl.parent_lookup_response::<BlockRequestState<Parent>>(id1, peer_id, None, D, &cx);
    rig.expect_empty_network();

    // Send the right block this time.
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id2,
        peer_id,
        Some(parent.into()),
        D,
        &cx,
    );
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &cx);
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
    bl.parent_lookup_response::<BlockRequestState<Parent>>(id1, peer_id, None, D, &cx);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id2,
        peer_id,
        Some(parent.into()),
        D,
        &cx,
    );
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &cx);
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
    bl.parent_lookup_failed::<BlockRequestState<Parent>>(
        id1,
        peer_id,
        &cx,
        RPCError::ErrorResponse(
            RPCResponseErrorCode::ResourceUnavailable,
            "older than deneb".into(),
        ),
    );
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id2,
        peer_id,
        Some(parent.into()),
        D,
        &cx,
    );
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        &mut cx,
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &cx);
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
                bl.parent_lookup_failed::<BlockRequestState<Parent>>(
                    id,
                    peer_id,
                    &cx,
                    RPCError::ErrorResponse(
                        RPCResponseErrorCode::ResourceUnavailable,
                        "older than deneb".into(),
                    ),
                );
            }
            _ => {
                // Send a bad block this time. It should be tried again.
                let bad_block = rig.rand_block(fork_name);
                bl.parent_lookup_response::<BlockRequestState<Parent>>(
                    id,
                    peer_id,
                    Some(bad_block.into()),
                    D,
                    &cx,
                );
                // Send the stream termination

                // Note, previously we would send the same lookup id with a stream terminator,
                // we'd ignore it because we'd intrepret it as an unrequested response, since
                // we already got one response for the block. I'm not sure what the intent is
                // for having this stream terminator line in this test at all. Receiving an invalid
                // block and a stream terminator with the same Id now results in two failed attempts,
                // I'm unsure if this is how it should behave?
                //
                bl.parent_lookup_response::<BlockRequestState<Parent>>(id, peer_id, None, D, &cx);
                rig.expect_penalty();
            }
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(
                bl.parent_lookups[0]
                    .current_parent_request
                    .block_request_state
                    .state
                    .failed_attempts(),
                dbg!(i)
            );
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
            bl.parent_lookup_failed::<BlockRequestState<Parent>>(
                id,
                peer_id,
                &cx,
                RPCError::ErrorResponse(
                    RPCResponseErrorCode::ResourceUnavailable,
                    "older than deneb".into(),
                ),
            );
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block(fork_name);
            bl.parent_lookup_response::<BlockRequestState<Parent>>(
                id,
                peer_id,
                Some(bad_block.into()),
                D,
                &cx,
            );
            rig.expect_penalty();
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(
                bl.parent_lookups[0]
                    .current_parent_request
                    .block_request_state
                    .state
                    .failed_attempts(),
                dbg!(i)
            );
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
        bl.parent_lookup_failed::<BlockRequestState<Parent>>(
            id,
            peer_id,
            &cx,
            RPCError::ErrorResponse(
                RPCResponseErrorCode::ResourceUnavailable,
                "older than deneb".into(),
            ),
        );
    }

    // Now fail processing a block in the parent request
    for i in 0..PROCESSING_FAILURES {
        let id = dbg!(rig.expect_parent_request(response_type));
        if matches!(fork_name, ForkName::Deneb) && i != 0 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        assert!(!bl.failed_chains.contains(&block_root));
        // send the right parent but fail processing
        bl.parent_lookup_response::<BlockRequestState<Parent>>(
            id,
            peer_id,
            Some(parent.clone()),
            D,
            &cx,
        );
        bl.parent_block_processed(block_root, BlockError::InvalidSignature.into(), &mut cx);
        bl.parent_lookup_response::<BlockRequestState<Parent>>(id, peer_id, None, D, &cx);
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
        bl.parent_lookup_response::<BlockRequestState<Parent>>(
            id,
            peer_id,
            Some(block.clone()),
            D,
            &cx,
        );
        // the stream termination
        bl.parent_lookup_response::<BlockRequestState<Parent>>(id, peer_id, None, D, &cx);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        bl.parent_block_processed(
            chain_hash,
            BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
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
    bl.search_block(block.canonical_root(), &[peer_id], &mut cx);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_lookup_response::<BlockRequestState<Current>>(
        id,
        peer_id,
        Some(block.into()),
        D,
        &cx,
    );
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_lookup_response::<BlockRequestState<Current>>(id, peer_id, None, D, &cx);
    // Send an Ignored response, the request should be dropped
    bl.single_block_component_processed::<BlockRequestState<Current>>(
        id.id,
        BlockProcessingResult::Ignored,
        &mut cx,
    );
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
    bl.parent_lookup_response::<BlockRequestState<Parent>>(
        id,
        peer_id,
        Some(parent.into()),
        D,
        &cx,
    );
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    bl.parent_block_processed(chain_hash, BlockProcessingResult::Ignored, &mut cx);
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
        bl.parent_lookup_response::<BlockRequestState<Parent>>(
            id,
            peer_id,
            Some(block.clone()),
            D,
            &cx,
        );
        // the stream termination
        bl.parent_lookup_response::<BlockRequestState<Parent>>(id, peer_id, None, D, &cx);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        if i + 2 == depth {
            // one block was removed
            bl.parent_block_processed(chain_hash, BlockError::BlockIsAlreadyKnown.into(), &mut cx)
        } else {
            bl.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
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
    bl.parent_chain_processed(chain_hash, process_result, &cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

mod deneb_only {
    use super::*;
    use crate::sync::block_lookups::common::ResponseType;
    use beacon_chain::data_availability_checker::AvailabilityCheckError;
    use beacon_chain::test_utils::NumBlobs;
    use ssz_types::VariableList;
    use std::ops::IndexMut;
    use std::str::FromStr;

    struct DenebTester {
        bl: BlockLookups<T>,
        cx: SyncNetworkContext<T>,
        rig: TestRig,
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Vec<Arc<BlobSidecar<E>>>,
        parent_block: VecDeque<Arc<SignedBeaconBlock<E>>>,
        parent_blobs: VecDeque<Vec<Arc<BlobSidecar<E>>>>,
        unknown_parent_block: Option<Arc<SignedBeaconBlock<E>>>,
        unknown_parent_blobs: Option<Vec<Arc<BlobSidecar<E>>>>,
        peer_id: PeerId,
        block_req_id: Option<SingleLookupReqId>,
        parent_block_req_id: Option<SingleLookupReqId>,
        blob_req_id: Option<SingleLookupReqId>,
        parent_blob_req_id: Option<SingleLookupReqId>,
        slot: Slot,
        block_root: Hash256,
    }

    enum RequestTrigger {
        AttestationUnknownBlock,
        GossipUnknownParentBlock { num_parents: usize },
        GossipUnknownParentBlob { num_parents: usize },
    }

    impl RequestTrigger {
        fn num_parents(&self) -> usize {
            match self {
                RequestTrigger::AttestationUnknownBlock => 0,
                RequestTrigger::GossipUnknownParentBlock { num_parents } => *num_parents,
                RequestTrigger::GossipUnknownParentBlob { num_parents } => *num_parents,
            }
        }
    }

    impl DenebTester {
        fn new(request_trigger: RequestTrigger) -> Option<Self> {
            let fork_name = get_fork_name();
            if !matches!(fork_name, ForkName::Deneb) {
                return None;
            }
            let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
            rig.harness.chain.slot_clock.set_slot(
                E::slots_per_epoch() * rig.harness.spec.deneb_fork_epoch.unwrap().as_u64(),
            );
            let (block, blobs) = rig.rand_block_and_blobs(fork_name, NumBlobs::Random);
            let mut block = Arc::new(block);
            let mut blobs = blobs.into_iter().map(Arc::new).collect::<Vec<_>>();
            let slot = block.slot();

            let num_parents = request_trigger.num_parents();
            let mut parent_block_chain = VecDeque::with_capacity(num_parents);
            let mut parent_blobs_chain = VecDeque::with_capacity(num_parents);
            for _ in 0..num_parents {
                // Set the current  block as the parent.
                let parent_root = block.canonical_root();
                let parent_block = block.clone();
                let parent_blobs = blobs.clone();
                parent_block_chain.push_front(parent_block);
                parent_blobs_chain.push_front(parent_blobs);

                // Create the next block.
                let (child_block, child_blobs) =
                    rig.block_with_parent_and_blobs(parent_root, get_fork_name(), NumBlobs::Random);
                let mut child_block = Arc::new(child_block);
                let mut child_blobs = child_blobs.into_iter().map(Arc::new).collect::<Vec<_>>();

                // Update the new block to the current block.
                std::mem::swap(&mut child_block, &mut block);
                std::mem::swap(&mut child_blobs, &mut blobs);
            }
            let block_root = block.canonical_root();
            let parent_root = block.parent_root();

            let peer_id = PeerId::random();

            // Trigger the request
            let (block_req_id, blob_req_id, parent_block_req_id, parent_blob_req_id) =
                match request_trigger {
                    RequestTrigger::AttestationUnknownBlock => {
                        bl.search_block(block_root, &[peer_id], &mut cx);
                        let block_req_id = rig.expect_lookup_request(ResponseType::Block);
                        let blob_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        (Some(block_req_id), Some(blob_req_id), None, None)
                    }
                    RequestTrigger::GossipUnknownParentBlock { .. } => {
                        bl.search_child_block(
                            block_root,
                            ChildComponents::new(block_root, Some(block.clone()), None, None),
                            &[peer_id],
                            &mut cx,
                        );

                        let blob_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        rig.expect_empty_network(); // expect no block request
                        bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);
                        let parent_block_req_id = rig.expect_parent_request(ResponseType::Block);
                        let parent_blob_req_id = rig.expect_parent_request(ResponseType::Blob);
                        (
                            None,
                            Some(blob_req_id),
                            Some(parent_block_req_id),
                            Some(parent_blob_req_id),
                        )
                    }
                    RequestTrigger::GossipUnknownParentBlob { .. } => {
                        let single_blob = blobs.first().cloned().unwrap();
                        let child_root = single_blob.block_root();

                        let mut lookup_blobs = FixedBlobSidecarList::default();
                        *lookup_blobs.index_mut(0) = Some(single_blob);
                        bl.search_child_block(
                            child_root,
                            ChildComponents::new(child_root, None, Some(lookup_blobs), None),
                            &[peer_id],
                            &mut cx,
                        );

                        let block_req_id = rig.expect_lookup_request(ResponseType::Block);
                        let blobs_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        rig.expect_empty_network(); // expect no block request
                        bl.search_parent(slot, child_root, parent_root, peer_id, &mut cx);
                        let parent_block_req_id = rig.expect_parent_request(ResponseType::Block);
                        let parent_blob_req_id = rig.expect_parent_request(ResponseType::Blob);
                        (
                            Some(block_req_id),
                            Some(blobs_req_id),
                            Some(parent_block_req_id),
                            Some(parent_blob_req_id),
                        )
                    }
                };

            Some(Self {
                bl,
                cx,
                rig,
                block,
                blobs,
                parent_block: parent_block_chain,
                parent_blobs: parent_blobs_chain,
                unknown_parent_block: None,
                unknown_parent_blobs: None,
                peer_id,
                block_req_id,
                parent_block_req_id,
                blob_req_id,
                parent_blob_req_id,
                slot,
                block_root,
            })
        }

        fn parent_block_response(mut self) -> Self {
            self.rig.expect_empty_network();
            let block = self.parent_block.pop_front().unwrap().clone();
            let _ = self.unknown_parent_block.insert(block.clone());
            self.bl.parent_lookup_response::<BlockRequestState<Parent>>(
                self.parent_block_req_id.expect("parent request id"),
                self.peer_id,
                Some(block),
                D,
                &self.cx,
            );

            assert_eq!(self.bl.parent_lookups.len(), 1);
            self
        }

        fn parent_blob_response(mut self) -> Self {
            let blobs = self.parent_blobs.pop_front().unwrap();
            let _ = self.unknown_parent_blobs.insert(blobs.clone());
            for blob in &blobs {
                self.bl
                    .parent_lookup_response::<BlobRequestState<Parent, E>>(
                        self.parent_blob_req_id.expect("parent blob request id"),
                        self.peer_id,
                        Some(blob.clone()),
                        D,
                        &self.cx,
                    );
                assert_eq!(self.bl.parent_lookups.len(), 1);
            }
            self.bl
                .parent_lookup_response::<BlobRequestState<Parent, E>>(
                    self.parent_blob_req_id.expect("blob request id"),
                    self.peer_id,
                    None,
                    D,
                    &self.cx,
                );

            self
        }

        fn block_response_triggering_process(self) -> Self {
            let mut me = self.block_response();
            me.rig.expect_block_process(ResponseType::Block);

            // The request should still be active.
            assert_eq!(me.bl.single_block_lookups.len(), 1);
            me
        }

        fn block_response(mut self) -> Self {
            // The peer provides the correct block, should not be penalized. Now the block should be sent
            // for processing.
            self.bl
                .single_lookup_response::<BlockRequestState<Current>>(
                    self.block_req_id.expect("block request id"),
                    self.peer_id,
                    Some(self.block.clone()),
                    D,
                    &self.cx,
                );
            self.rig.expect_empty_network();

            // The request should still be active.
            assert_eq!(self.bl.single_block_lookups.len(), 1);
            self
        }

        fn blobs_response(mut self) -> Self {
            for blob in &self.blobs {
                self.bl
                    .single_lookup_response::<BlobRequestState<Current, E>>(
                        self.blob_req_id.expect("blob request id"),
                        self.peer_id,
                        Some(blob.clone()),
                        D,
                        &self.cx,
                    );
                assert_eq!(self.bl.single_block_lookups.len(), 1);
            }
            self.bl
                .single_lookup_response::<BlobRequestState<Current, E>>(
                    self.blob_req_id.expect("blob request id"),
                    self.peer_id,
                    None,
                    D,
                    &self.cx,
                );
            self
        }

        fn blobs_response_was_valid(mut self) -> Self {
            self.rig.expect_empty_network();
            if !self.blobs.is_empty() {
                self.rig.expect_block_process(ResponseType::Blob);
            }
            self
        }

        fn expect_empty_beacon_processor(mut self) -> Self {
            self.rig.expect_empty_beacon_processor();
            self
        }

        fn empty_block_response(mut self) -> Self {
            self.bl
                .single_lookup_response::<BlockRequestState<Current>>(
                    self.block_req_id.expect("block request id"),
                    self.peer_id,
                    None,
                    D,
                    &self.cx,
                );
            self
        }

        fn empty_blobs_response(mut self) -> Self {
            self.bl
                .single_lookup_response::<BlobRequestState<Current, E>>(
                    self.blob_req_id.expect("blob request id"),
                    self.peer_id,
                    None,
                    D,
                    &self.cx,
                );
            self
        }

        fn empty_parent_block_response(mut self) -> Self {
            self.bl.parent_lookup_response::<BlockRequestState<Parent>>(
                self.parent_block_req_id.expect("block request id"),
                self.peer_id,
                None,
                D,
                &self.cx,
            );
            self
        }

        fn empty_parent_blobs_response(mut self) -> Self {
            self.bl
                .parent_lookup_response::<BlobRequestState<Parent, E>>(
                    self.parent_blob_req_id.expect("blob request id"),
                    self.peer_id,
                    None,
                    D,
                    &self.cx,
                );
            self
        }

        fn block_imported(mut self) -> Self {
            // Missing blobs should be the request is not removed, the outstanding blobs request should
            // mean we do not send a new request.
            self.bl
                .single_block_component_processed::<BlockRequestState<Current>>(
                    self.block_req_id.expect("block request id").id,
                    BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(
                        self.block_root,
                    )),
                    &mut self.cx,
                );
            self.rig.expect_empty_network();
            assert_eq!(self.bl.single_block_lookups.len(), 0);
            self
        }

        fn parent_block_imported(mut self) -> Self {
            self.bl.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
                &mut self.cx,
            );
            self.rig.expect_empty_network();
            assert_eq!(self.bl.parent_lookups.len(), 0);
            self
        }

        fn parent_block_unknown_parent(mut self) -> Self {
            let block = self.unknown_parent_block.take().unwrap();
            let block = RpcBlock::new(
                Some(block.canonical_root()),
                block,
                self.unknown_parent_blobs.take().map(VariableList::from),
                None,
            )
            .unwrap();
            self.bl.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Err(BlockError::ParentUnknown(block)),
                &mut self.cx,
            );
            assert_eq!(self.bl.parent_lookups.len(), 1);
            self
        }

        fn invalid_parent_processed(mut self) -> Self {
            self.bl.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Err(BlockError::ProposalSignatureInvalid),
                &mut self.cx,
            );
            assert_eq!(self.bl.parent_lookups.len(), 1);
            self
        }

        fn invalid_block_processed(mut self) -> Self {
            self.bl
                .single_block_component_processed::<BlockRequestState<Current>>(
                    self.block_req_id.expect("block request id").id,
                    BlockProcessingResult::Err(BlockError::ProposalSignatureInvalid),
                    &mut self.cx,
                );
            assert_eq!(self.bl.single_block_lookups.len(), 1);
            self
        }

        fn invalid_blob_processed(mut self) -> Self {
            self.bl
                .single_block_component_processed::<BlobRequestState<Current, E>>(
                    self.blob_req_id.expect("blob request id").id,
                    BlockProcessingResult::Err(BlockError::AvailabilityCheck(
                        AvailabilityCheckError::KzgVerificationFailed,
                    )),
                    &mut self.cx,
                );
            assert_eq!(self.bl.single_block_lookups.len(), 1);
            self
        }

        fn missing_components_from_block_request(mut self) -> Self {
            self.bl
                .single_block_component_processed::<BlockRequestState<Current>>(
                    self.block_req_id.expect("block request id").id,
                    BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                        self.slot,
                        self.block_root,
                    )),
                    &mut self.cx,
                );
            assert_eq!(self.bl.single_block_lookups.len(), 1);
            self
        }

        fn missing_components_from_blob_request(mut self) -> Self {
            self.bl
                .single_block_component_processed::<BlobRequestState<Current, E>>(
                    self.blob_req_id.expect("blob request id").id,
                    BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                        self.slot,
                        self.block_root,
                    )),
                    &mut self.cx,
                );
            assert_eq!(self.bl.single_block_lookups.len(), 1);
            self
        }

        fn expect_penalty(mut self) -> Self {
            self.rig.expect_penalty();
            self
        }
        fn expect_no_penalty(mut self) -> Self {
            self.rig.expect_empty_network();
            self
        }
        fn expect_block_request(mut self) -> Self {
            let id = self.rig.expect_lookup_request(ResponseType::Block);
            self.block_req_id = Some(id);
            self
        }
        fn expect_blobs_request(mut self) -> Self {
            let id = self.rig.expect_lookup_request(ResponseType::Blob);
            self.blob_req_id = Some(id);
            self
        }
        fn expect_parent_block_request(mut self) -> Self {
            let id = self.rig.expect_parent_request(ResponseType::Block);
            self.parent_block_req_id = Some(id);
            self
        }
        fn expect_parent_blobs_request(mut self) -> Self {
            let id = self.rig.expect_parent_request(ResponseType::Blob);
            self.parent_blob_req_id = Some(id);
            self
        }
        fn expect_no_blobs_request(mut self) -> Self {
            self.rig.expect_empty_network();
            self
        }
        fn expect_no_block_request(mut self) -> Self {
            self.rig.expect_empty_network();
            self
        }
        fn invalidate_blobs_too_few(mut self) -> Self {
            self.blobs.pop().expect("blobs");
            self
        }
        fn invalidate_blobs_too_many(mut self) -> Self {
            let first_blob = self.blobs.first().expect("blob").clone();
            self.blobs.push(first_blob);
            self
        }
        fn expect_parent_chain_process(mut self) -> Self {
            self.rig.expect_parent_chain_process();
            self
        }
        fn expect_block_process(mut self) -> Self {
            self.rig.expect_block_process(ResponseType::Block);
            self
        }
    }

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
    fn single_block_and_blob_lookup_block_returned_first_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .blobs_response()
            .blobs_response_was_valid()
            .block_imported();
    }

    #[test]
    fn single_block_and_blob_lookup_blobs_returned_first_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .blobs_response()
            .blobs_response_was_valid()
            .block_response_triggering_process()
            .block_imported();
    }

    #[test]
    fn single_block_and_blob_lookup_empty_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .empty_block_response()
            .expect_penalty()
            .expect_block_request()
            .expect_no_blobs_request()
            .empty_blobs_response()
            .expect_empty_beacon_processor()
            .expect_no_penalty()
            .expect_no_block_request()
            .expect_no_blobs_request()
            .block_response_triggering_process()
            .missing_components_from_block_request();
    }

    #[test]
    fn single_block_response_then_empty_blob_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .missing_components_from_block_request()
            .empty_blobs_response()
            .missing_components_from_blob_request()
            .expect_penalty()
            .expect_blobs_request()
            .expect_no_block_request();
    }

    #[test]
    fn single_blob_response_then_empty_block_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .blobs_response()
            .blobs_response_was_valid()
            .expect_no_penalty()
            .expect_no_block_request()
            .expect_no_blobs_request()
            .missing_components_from_blob_request()
            .empty_block_response()
            .expect_penalty()
            .expect_block_request()
            .expect_no_blobs_request();
    }

    #[test]
    fn single_invalid_block_response_then_blob_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .invalid_block_processed()
            .expect_penalty()
            .expect_block_request()
            .expect_no_blobs_request()
            .blobs_response()
            .missing_components_from_blob_request()
            .expect_no_penalty()
            .expect_no_block_request()
            .expect_no_block_request();
    }

    #[test]
    fn single_block_response_then_invalid_blob_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .missing_components_from_block_request()
            .blobs_response()
            .invalid_blob_processed()
            .expect_penalty()
            .expect_blobs_request()
            .expect_no_block_request();
    }

    #[test]
    fn single_block_response_then_too_few_blobs_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .missing_components_from_block_request()
            .invalidate_blobs_too_few()
            .blobs_response()
            .missing_components_from_blob_request()
            .expect_penalty()
            .expect_blobs_request()
            .expect_no_block_request();
    }

    #[test]
    fn single_block_response_then_too_many_blobs_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .invalidate_blobs_too_many()
            .blobs_response()
            .expect_penalty()
            .expect_blobs_request()
            .expect_no_block_request();
    }
    #[test]
    fn too_few_blobs_response_then_block_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .invalidate_blobs_too_few()
            .blobs_response()
            .blobs_response_was_valid()
            .expect_no_penalty()
            .expect_no_blobs_request()
            .expect_no_block_request()
            .block_response_triggering_process();
    }

    #[test]
    fn too_many_blobs_response_then_block_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .invalidate_blobs_too_many()
            .blobs_response()
            .expect_penalty()
            .expect_blobs_request()
            .expect_no_block_request()
            .block_response_triggering_process();
    }

    #[test]
    fn parent_block_unknown_parent() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .blobs_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_parent_blobs_request()
            .expect_empty_beacon_processor();
    }

    #[test]
    fn parent_block_invalid_parent() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .blobs_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .invalid_parent_processed()
            .expect_penalty()
            .expect_parent_block_request()
            .expect_parent_blobs_request()
            .expect_empty_beacon_processor();
    }

    #[test]
    fn parent_block_and_blob_lookup_parent_returned_first() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .blobs_response()
            .expect_parent_chain_process();
    }

    #[test]
    fn parent_block_and_blob_lookup_child_returned_first() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .blobs_response()
            .expect_no_penalty()
            .expect_no_block_request()
            .expect_no_blobs_request()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .expect_parent_chain_process();
    }

    #[test]
    fn empty_parent_block_then_parent_blob() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .empty_parent_block_response()
            .expect_penalty()
            .expect_parent_block_request()
            .expect_no_blobs_request()
            .parent_blob_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .expect_block_process()
            .parent_block_imported()
            .blobs_response()
            .expect_parent_chain_process();
    }

    #[test]
    fn empty_parent_blobs_then_parent_block() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .blobs_response()
            .empty_parent_blobs_response()
            .expect_no_penalty()
            .expect_no_blobs_request()
            .expect_no_block_request()
            .parent_block_response()
            .expect_penalty()
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .expect_parent_chain_process();
    }

    #[test]
    fn parent_blob_unknown_parent() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .block_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_parent_blobs_request()
            .expect_empty_beacon_processor();
    }

    #[test]
    fn parent_blob_invalid_parent() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .block_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .invalid_parent_processed()
            .expect_penalty()
            .expect_parent_block_request()
            .expect_parent_blobs_request()
            .expect_empty_beacon_processor();
    }

    #[test]
    fn parent_block_and_blob_lookup_parent_returned_first_blob_trigger() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .block_response()
            .expect_parent_chain_process();
    }

    #[test]
    fn parent_block_and_blob_lookup_child_returned_first_blob_trigger() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .block_response()
            .expect_no_penalty()
            .expect_no_block_request()
            .expect_no_blobs_request()
            .parent_block_response()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .expect_parent_chain_process();
    }

    #[test]
    fn empty_parent_block_then_parent_blob_blob_trigger() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .empty_parent_block_response()
            .expect_penalty()
            .expect_parent_block_request()
            .expect_no_blobs_request()
            .parent_blob_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .expect_block_process()
            .parent_block_imported()
            .block_response()
            .expect_parent_chain_process();
    }

    #[test]
    fn empty_parent_blobs_then_parent_block_blob_trigger() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .block_response()
            .empty_parent_blobs_response()
            .expect_no_penalty()
            .expect_no_blobs_request()
            .expect_no_block_request()
            .parent_block_response()
            .expect_penalty()
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_imported()
            .expect_parent_chain_process();
    }

    #[test]
    fn parent_blob_unknown_parent_chain() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 2 })
        else {
            return;
        };

        tester
            .block_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_no_penalty()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_parent_blobs_request()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .parent_blob_response()
            .expect_no_penalty()
            .expect_block_process();
    }
}
