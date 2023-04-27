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
    BeaconBlock, ForkName, MinimalEthSpec as E, SignedBeaconBlock,
};

type T = Witness<TestingSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

struct TestRig {
    beacon_processor_rx: mpsc::Receiver<WorkEvent<T>>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    rng: XorShiftRng,
}

const D: Duration = Duration::new(0, 0);

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

        let chain = harness.chain;

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(100);
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let rng = XorShiftRng::from_seed([42; 16]);
        let rig = TestRig {
            beacon_processor_rx,
            network_rx,
            rng,
        };

        //TODO(sean) add a data availability checker to the harness and use that one
        let da_checker = Arc::new(DataAvailabilityChecker::new(
            chain.slot_clock.clone(),
            None,
            chain.spec.clone(),
        ));

        let bl = BlockLookups::new(
            da_checker,
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
        let inner = map_fork_name!(fork_name, BeaconBlock, <_>::random_for_test(&mut self.rng));
        SignedBeaconBlock::from_block(inner, types::Signature::random_for_test(&mut self.rng))
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
        let mut inner = map_fork_name!(fork_name, BeaconBlock, <_>::random_for_test(&mut self.rng));

        *inner.parent_root_mut() = parent_root;
        SignedBeaconBlock::from_block(inner, types::Signature::random_for_test(&mut self.rng))
    }
}

#[test]
fn test_single_block_lookup_happy_path() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = rig.rand_block(fork_name);
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    // Trigger the request
    bl.search_block(block_root, peer_id, PeerShouldHave::BlockAndBlobs, &mut cx);
    let id = rig.expect_block_request(response_type);

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
        ResponseType::Block,
        &mut cx,
    );
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_single_block_lookup_empty_response() {
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, PeerShouldHave::BlockAndBlobs, &mut cx);
    let id = rig.expect_block_request(response_type);

    // The peer does not have the block. It should be penalized.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    rig.expect_penalty();

    rig.expect_block_request(response_type); // it should be retried
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, PeerShouldHave::BlockAndBlobs, &mut cx);
    let id = rig.expect_block_request(response_type);

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

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, PeerShouldHave::BlockAndBlobs, &mut cx);
    let id = rig.expect_block_request(response_type);

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    bl.single_block_lookup_failed(id, &peer_id, &mut cx, RPCError::UnsupportedProtocol);
    rig.expect_block_request(response_type);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_becomes_parent_request() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = Arc::new(rig.rand_block(fork_name));
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(
        block.canonical_root(),
        peer_id,
        PeerShouldHave::BlockAndBlobs,
        &mut cx,
    );
    let id = rig.expect_block_request(response_type);

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
        ResponseType::Block,
        &mut cx,
    );
    assert_eq!(bl.single_block_lookups.len(), 1);
    rig.expect_parent_request(response_type);
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 1);
}

#[test]
fn test_parent_lookup_happy_path() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(
        chain_hash,
        BlockError::BlockIsAlreadyKnown.into(),
        ResponseType::Block,
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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
        ResponseType::Block,
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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
        ResponseType::Block,
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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
        ResponseType::Block,
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    const PROCESSING_FAILURES: u8 = parent_lookup::PARENT_FAIL_TOLERANCE / 2 + 1;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = Arc::new(rig.rand_block(fork_name));
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let peer_id = PeerId::random();
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let slot = block.slot();

    // Trigger the request
    bl.search_parent(slot, block_root, parent_root, peer_id, &mut cx);

    // Fail downloading the block
    for _ in 0..(parent_lookup::PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_parent_request(response_type);
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
        assert!(!bl.failed_chains.contains(&block_root));
        // send the right parent but fail processing
        bl.parent_lookup_response(id, peer_id, Some(parent.clone()), D, &mut cx);
        bl.parent_block_processed(
            block_root,
            BlockError::InvalidSignature.into(),
            ResponseType::Block,
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
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
            ResponseType::Block,
            &mut cx,
        )
    }

    rig.expect_penalty();
    assert!(bl.failed_chains.contains(&chain_hash));
}

#[test]
fn test_parent_lookup_disconnection() {
    let fork_name = ForkName::Base;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let peer_id = PeerId::random();
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
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = rig.rand_block(fork_name);
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(
        block.canonical_root(),
        peer_id,
        PeerShouldHave::BlockAndBlobs,
        &mut cx,
    );
    let id = rig.expect_block_request(response_type);

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
    bl.single_block_processed(
        id,
        BlockProcessingResult::Ignored,
        ResponseType::Block,
        &mut cx,
    );
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_ignored_response() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

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

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    bl.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ignored,
        ResponseType::Block,
        &mut cx,
    );
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 0);
}

/// This is a regression test.
#[test]
fn test_same_chain_race_condition() {
    let fork_name = ForkName::Base;
    let response_type = ResponseType::Block;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(true);

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
                ResponseType::Block,
                &mut cx,
            )
        } else {
            bl.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(block.into()).into(),
                ResponseType::Block,
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
