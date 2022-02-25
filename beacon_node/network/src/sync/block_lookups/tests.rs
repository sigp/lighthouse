use std::sync::Arc;

use crate::service::RequestId;
use crate::sync::manager::RequestId as SyncId;
use crate::NetworkMessage;

use super::*;

use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use lighthouse_network::{NetworkGlobals, Request};
use slog::{Drain, Level};
use slot_clock::SystemTimeSlotClock;
use store::MemoryStore;
use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use types::MinimalEthSpec as E;

type T = Witness<SystemTimeSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

struct TestRig {
    beacon_processor_rx: mpsc::Receiver<WorkEvent<T>>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    rng: XorShiftRng,
}

impl TestRig {
    fn test_setup(log_level: Option<Level>) -> (BlockLookups<T>, SyncNetworkContext<E>, Self) {
        let log = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();

            if let Some(log_level) = log_level {
                slog::Logger::root(drain.filter_level(log_level).fuse(), slog::o!())
            } else {
                slog::Logger::root(drain.filter(|_| false).fuse(), slog::o!())
            }
        };

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(10);
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let rng = XorShiftRng::from_seed([42; 16]);
        let rig = TestRig {
            beacon_processor_rx,
            network_rx,
            rng,
        };
        let bl = BlockLookups::new(
            beacon_processor_tx,
            log.new(slog::o!("component" => "block_lookups")),
        );
        let cx = {
            let globals = Arc::new(NetworkGlobals::new_test_globals(&log));
            SyncNetworkContext::new(
                network_tx,
                globals.clone(),
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

    fn expect_block_request(&mut self) -> Id {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(_request),
                request_id: RequestId::Sync(SyncId::SingleBlock { id }),
            }) => {
                println!("found id: {}", id);
                return id;
            }
            other => {
                panic!("Expected block request, found {:?}", other);
            }
        }
    }

    fn expect_parent_request(&mut self) -> Id {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(_request),
                request_id: RequestId::Sync(SyncId::ParentLookup { id }),
            }) => return id,
            other => panic!("Expected parent request, found {:?}", other),
        }
    }

    fn expect_block_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                assert_eq!(work.work_type(), crate::beacon_processor::RPC_BLOCK);
            }
            other => panic!("Expected block process, found {:?}", other),
        }
    }

    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                assert_eq!(work.work_type(), crate::beacon_processor::CHAIN_SEGMENT);
            }
            other => panic!("Expected chain segment process, found {:?}", other),
        }
    }

    fn expect_empty_network(&mut self) {
        assert_eq!(
            self.network_rx.try_recv().expect_err("must err"),
            mpsc::error::TryRecvError::Empty
        );
    }

    pub fn expect_penalty(&mut self) {
        match self.network_rx.try_recv() {
            Ok(NetworkMessage::ReportPeer { .. }) => {}
            other => panic!("Expected peer penalty, found {:?}", other),
        }
    }
}

#[test]
fn test_single_block_lookup() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(Some(Level::Debug));

    let block = rig.rand_block();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block.canonical_root(), peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    bl.single_block_lookup_response(id, peer_id, Some(Box::new(block)), &mut cx);
    rig.expect_empty_network();
    rig.expect_block_process();

    // The request should still be active.
    assert_eq!(bl.single_block_lookups.len(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed.
    bl.single_block_lookup_response(id, peer_id, None, &mut cx);
    rig.expect_empty_network();
    assert_eq!(bl.single_block_lookups.len(), 0);
}

#[test]
fn test_single_block_lookup_empty_response() {
    let (mut bl, mut cx, mut rig) = TestRig::test_setup(Some(Level::Debug));

    let block_hash = Hash256::random();
    let peer_id = PeerId::random();

    // Trigger the request
    bl.search_block(block_hash, peer_id, &mut cx);
    let id = rig.expect_block_request();

    // The peer does not have the block. It should be penalized.
    bl.single_block_lookup_response(id, peer_id, None, &mut cx);
    rig.expect_penalty();

    // The request should not be active
    assert_eq!(bl.single_block_lookups.len(), 0);
    rig.expect_empty_network();
}
