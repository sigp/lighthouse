/*use std::sync::Arc;

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
use lighthouse_network::{NetworkGlobals, Request};
use slot_clock::SystemTimeSlotClock;
use std::time::Duration;
use store::MemoryStore;
use tokio::sync::mpsc;
use types::{
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
    MinimalEthSpec as E, SignedBeaconBlock,
};

type T = Witness<SystemTimeSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

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
        let bl = BlockLookups::new(log.new(slog::o!("component" => "block_lookups")));
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

    fn rand_block(&mut self) -> SignedBeaconBlock<E> {
        SignedBeaconBlock::from_block(
            types::BeaconBlock::Base(types::BeaconBlockBase {
                ..<_>::random_for_test(&mut self.rng)
            }),
            types::Signature::random_for_test(&mut self.rng),
        )
    }

    #[track_caller]
    fn expect_block_request(&mut self) -> Id {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(_request),
                request_id: RequestId::Sync(SyncId::SingleBlock { id }),
            }) => id,
            other => {
                panic!("Expected block request, found {:?}", other);
            }
        }
    }

    #[track_caller]
    fn expect_parent_request(&mut self) -> Id {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(_request),
                request_id: RequestId::Sync(SyncId::ParentLookup { id }),
            }) => id,
            other => panic!("Expected parent request, found {:?}", other),
        }
    }

    #[track_caller]
    fn expect_block_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                assert_eq!(work.work_type(), crate::beacon_processor::RPC_BLOCK);
            }
            other => panic!("Expected block process, found {:?}", other),
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

    pub fn block_with_parent(&mut self, parent_root: Hash256) -> SignedBeaconBlock<E> {
        SignedBeaconBlock::from_block(
            types::BeaconBlock::Base(types::BeaconBlockBase {
                parent_root,
                ..<_>::random_for_test(&mut self.rng)
            }),
            types::Signature::random_for_test(&mut self.rng),
        )
    }
}

#[test]
fn test_single_block_lookup_happy_path() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = rig.rand_block();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block.canonical_root(), peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.into()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process();

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    bl.single_block_processed(id, Ok(()).into(), &mut cx);
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_single_block_lookup_empty_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer does not have the block. It should be penalized.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    rig.expect_penalty();

    rig.expect_block_request(); // it should be retried
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, &mut cx);
    let id = rig.expect_block_request();

    // Peer sends something else. It should be penalized.
    let bad_block = rig.rand_block();
    bl.single_block_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
    rig.expect_penalty();
    rig.expect_block_request(); // should be retried

    // Send the stream termination. This should not produce an additional penalty.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_failure() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    bl.single_block_lookup_failed(id, &mut cx);
    rig.expect_block_request();
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_becomes_parent_request() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = rig.rand_block();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block.canonical_root(), peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.clone().into()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process();

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request moved to a
    // parent request after processing.
    bl.single_block_processed(id, BlockError::ParentUnknown(block.into()).into(), &mut cx);
    assert_eq!(bl.single_block_lookups.len(), 0);
    rig.expect_parent_request();
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 1);
}

#[test]
fn test_parent_lookup_happy_path() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    let id = rig.expect_parent_request();

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process();
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(chain_hash, BlockError::BlockIsAlreadyKnown.into(), &mut cx);
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_wrong_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    let id1 = rig.expect_parent_request();

    // Peer sends the wrong block, peer should be penalized and the block re-requested.
    let bad_block = rig.rand_block();
    bl.parent_lookup_response(id1, peer_id, Some(bad_block.into()), D, &mut cx);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request();

    // Send the stream termination for the first request. This should not produce extra penalties.
    bl.parent_lookup_response(id1, peer_id, None, D, &mut cx);
    rig.expect_empty_network();

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(chain_hash, Ok(()).into(), &mut cx);
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_empty_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    let id1 = rig.expect_parent_request();

    // Peer sends an empty response, peer should be penalized and the block re-requested.
    bl.parent_lookup_response(id1, peer_id, None, D, &mut cx);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request();

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(chain_hash, Ok(()).into(), &mut cx);
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_rpc_failure() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    let id1 = rig.expect_parent_request();

    // The request fails. It should be tried again.
    bl.parent_lookup_failed(
        id1,
        peer_id,
        &mut cx,
        RPCError::ErrorResponse(
            RPCResponseErrorCode::ResourceUnavailable,
            "older than eip4844".into(),
        ),
    );
    let id2 = rig.expect_parent_request();

    // Send the right block this time.
    bl.parent_lookup_response(id2, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    bl.parent_block_processed(chain_hash, Ok(()).into(), &mut cx);
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_many_attempts() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        let id = rig.expect_parent_request();
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
                        "older than eip4844".into(),
                    ),
                );
            }
            _ => {
                // Send a bad block this time. It should be tried again.
                let bad_block = rig.rand_block();
                bl.parent_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
                // Send the stream termination
                bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
                rig.expect_penalty();
            }
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(bl.parent_lookups[0].failed_attempts(), dbg!(i));
        }
    }

    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_many_download_attempts_no_blacklist() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let block_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(block_hash, block.into(), peer_id, &mut cx);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        assert!(!bl.failed_chains.contains(&block_hash));
        let id = rig.expect_parent_request();
        if i % 2 != 0 {
            // The request fails. It should be tried again.
            bl.parent_lookup_failed(
                id,
                peer_id,
                &mut cx,
                RPCError::ErrorResponse(
                    RPCResponseErrorCode::ResourceUnavailable,
                    "older than eip4844".into(),
                ),
            );
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block();
            bl.parent_lookup_response(id, peer_id, Some(bad_block.into()), D, &mut cx);
            rig.expect_penalty();
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            assert_eq!(bl.parent_lookups[0].failed_attempts(), dbg!(i));
        }
    }

    assert_eq!(bl.parent_lookups.len(), 0);
    assert!(!bl.failed_chains.contains(&block_hash));
    assert!(!bl.failed_chains.contains(&parent.canonical_root()));
}

#[test]
fn test_parent_lookup_too_many_processing_attempts_must_blacklist() {
    const PROCESSING_FAILURES: u8 = parent_lookup::PARENT_FAIL_TOLERANCE / 2 + 1;
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = Arc::new(rig.rand_block());
    let block = rig.block_with_parent(parent.canonical_root());
    let block_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(block_hash, block.into(), peer_id, &mut cx);

    // Fail downloading the block
    for _ in 0..(parent_lookup::PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_parent_request();
        // The request fails. It should be tried again.
        bl.parent_lookup_failed(
            id,
            peer_id,
            &mut cx,
            RPCError::ErrorResponse(
                RPCResponseErrorCode::ResourceUnavailable,
                "older than eip4844".into(),
            ),
        );
    }

    // Now fail processing a block in the parent request
    for _ in 0..PROCESSING_FAILURES {
        let id = dbg!(rig.expect_parent_request());
        assert!(!bl.failed_chains.contains(&block_hash));
        // send the right parent but fail processing
        bl.parent_lookup_response(id, peer_id, Some(parent.clone().into()), D, &mut cx);
        bl.parent_block_processed(block_hash, BlockError::InvalidSignature.into(), &mut cx);
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        rig.expect_penalty();
    }

    assert!(bl.failed_chains.contains(&block_hash));
    assert_eq!(bl.parent_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_too_deep() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);
    let mut blocks =
        Vec::<SignedBeaconBlock<E>>::with_capacity(parent_lookup::PARENT_DEPTH_TOLERANCE);
    while blocks.len() < parent_lookup::PARENT_DEPTH_TOLERANCE {
        let parent = blocks
            .last()
            .map(|b| b.canonical_root())
            .unwrap_or_else(Hash256::random);
        let block = rig.block_with_parent(parent);
        blocks.push(block);
    }

    let peer_id = PeerId::random();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    bl.search_parent(chain_hash, trigger_block.into(), peer_id, &mut cx);

    for block in blocks.into_iter().rev() {
        let id = rig.expect_parent_request();
        // the block
        bl.parent_lookup_response(id, peer_id, Some(block.clone().into()), D, &mut cx);
        // the stream termination
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        // the processing request
        rig.expect_block_process();
        // the processing result
        bl.parent_block_processed(
            chain_hash,
            BlockError::ParentUnknown(block.into()).into(),
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
    let trigger_block = rig.rand_block();
    bl.search_parent(
        trigger_block.canonical_root(),
        trigger_block.into(),
        peer_id,
        &mut cx,
    );
    bl.peer_disconnected(&peer_id, &mut cx);
    assert!(bl.parent_lookups.is_empty());
}

#[test]
fn test_single_block_lookup_ignored_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let block = rig.rand_block();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block.canonical_root(), peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(block.into()), D, &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process();

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    bl.single_block_lookup_response(id, peer_id, None, D, &mut cx);
    // Send an Ignored response, the request should be dropped
    bl.single_block_processed(id, BlockProcessResult::Ignored, &mut cx);
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_parent_lookup_ignored_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(false);

    let parent = rig.rand_block();
    let block = rig.block_with_parent(parent.canonical_root());
    let chain_hash = block.canonical_root();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_parent(chain_hash, block.into(), peer_id, &mut cx);
    let id = rig.expect_parent_request();

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    bl.parent_lookup_response(id, peer_id, Some(parent.into()), D, &mut cx);
    rig.expect_block_process();
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    bl.parent_block_processed(chain_hash, BlockProcessResult::Ignored, &mut cx);
    rig.expect_empty_network();
    assert_eq!(bl.parent_lookups.len(), 0);
}

/// This is a regression test.
#[test]
fn test_same_chain_race_condition() {
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
        let block = Arc::new(rig.block_with_parent(parent));
        blocks.push(block);
    }

    let peer_id = PeerId::random();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    bl.search_parent(chain_hash, trigger_block.clone().into(), peer_id, &mut cx);

    for (i, block) in blocks.into_iter().rev().enumerate() {
        let id = rig.expect_parent_request();
        // the block
        bl.parent_lookup_response(id, peer_id, Some(block.clone().into()), D, &mut cx);
        // the stream termination
        bl.parent_lookup_response(id, peer_id, None, D, &mut cx);
        // the processing request
        rig.expect_block_process();
        // the processing result
        if i + 2 == depth {
            // one block was removed
            bl.parent_block_processed(chain_hash, BlockError::BlockIsAlreadyKnown.into(), &mut cx)
        } else {
            bl.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(block.into()).into(),
                &mut cx,
            )
        }
        parent_lookups_consistency(&bl)
    }

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.expect_parent_chain_process();

    // Try to get this block again while the chain is being processed. We should not request it again.
    let peer_id = PeerId::random();
    bl.search_parent(chain_hash, trigger_block.into(), peer_id, &mut cx);
    parent_lookups_consistency(&bl);

    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    bl.parent_chain_processed(chain_hash, process_result, &mut cx);
    assert_eq!(bl.parent_lookups.len(), 0);
}*/
