use crate::network_beacon_processor::NetworkBeaconProcessor;

use crate::service::RequestId;
use crate::sync::manager::{RequestId as SyncRequestId, SingleLookupReqId, SyncManager};
use crate::sync::SyncMessage;
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
use lighthouse_network::types::SyncState;
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
    network_rx_queue: Vec<NetworkMessage<E>>,
    rng: XorShiftRng,
    harness: BeaconChainHarness<T>,
    sync_manager: SyncManager<T>,
    beacon_processor: Arc<NetworkBeaconProcessor<T>>,
}

const D: Duration = Duration::new(0, 0);

impl TestRig {
    fn test_setup() -> Self {
        let enable_log = cfg!(feature = "test_logger");
        let log = build_log(slog::Level::Trace, enable_log);

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
        let (beacon_processor, beacon_processor_rx) = NetworkBeaconProcessor::null_for_testing(
            globals,
            chain.clone(),
            harness.runtime.task_executor.clone(),
            log.clone(),
        );

        let (_sync_send, sync_recv) = mpsc::unbounded_channel::<SyncMessage<E>>();

        // All current tests expect synced and EL online state
        let beacon_processor = Arc::new(beacon_processor);
        beacon_processor
            .network_globals
            .set_sync_state(SyncState::Synced);

        let rng = XorShiftRng::from_seed([42; 16]);
        let rig = TestRig {
            beacon_processor_rx,
            network_rx,
            network_rx_queue: vec![],
            rng,
            harness,
            beacon_processor: beacon_processor.clone(),
            sync_manager: SyncManager::new(
                chain,
                network_tx,
                beacon_processor,
                sync_recv,
                log.clone(),
            ),
        };

        rig
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

    fn send_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.handle_message(sync_message);
    }

    fn active_single_lookups_count(&self) -> usize {
        self.sync_manager.active_single_lookups().len()
    }

    fn active_parent_lookups(&self) -> Vec<Hash256> {
        self.sync_manager.active_parent_lookups()
    }

    fn active_parent_lookups_count(&self) -> usize {
        self.sync_manager.active_parent_lookups().len()
    }

    fn failed_chains_contains(&mut self, chain_hash: &Hash256) -> bool {
        self.sync_manager.failed_chains_contains(chain_hash)
    }

    #[track_caller]
    fn assert_parent_lookups_consistency(&self) {
        let hashes = self.active_parent_lookups();
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

    fn new_connected_peer(&mut self) -> PeerId {
        let peer_id = PeerId::random();
        self.beacon_processor
            .network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(&peer_id);
        peer_id
    }

    fn search_block(&mut self, block_root: Hash256, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
            peer_id, block_root,
        ));
    }

    fn search_parent(&mut self, block: Arc<SignedBeaconBlock<E>>, peer_id: PeerId) {
        let block_root = block.canonical_root();
        self.send_sync_message(SyncMessage::UnknownParentBlock(
            peer_id,
            RpcBlock::new_without_blobs(Some(block_root), block),
            block_root,
        ))
    }

    fn parent_chain_processed(&mut self, chain_hash: Hash256, result: BatchProcessResult) {
        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: ChainSegmentProcessId::ParentLookup(chain_hash),
            result,
        })
    }

    fn parent_block_processed(&mut self, chain_hash: Hash256, result: BlockProcessingResult<E>) {
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::ParentLookup { chain_hash },
            result,
        });
    }

    fn single_block_component_processed(
        &mut self,
        id: SingleLookupReqId,
        result: BlockProcessingResult<E>,
    ) {
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::SingleBlock { id: id.id },
            result,
        })
    }

    fn single_blob_component_processed(
        &mut self,
        id: SingleLookupReqId,
        result: BlockProcessingResult<E>,
    ) {
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::SingleBlob { id: id.id },
            result,
        })
    }

    fn parent_lookup_block_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<E>>>,
    ) {
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::ParentLookup { id },
            peer_id,
            beacon_block,
            seen_timestamp: D,
        });
    }

    fn single_lookup_block_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<E>>>,
    ) {
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::SingleBlock { id },
            peer_id,
            beacon_block,
            seen_timestamp: D,
        });
    }

    fn parent_lookup_blob_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        blob_sidecar: Option<Arc<BlobSidecar<E>>>,
    ) {
        self.send_sync_message(SyncMessage::RpcBlob {
            request_id: SyncRequestId::ParentLookupBlob { id },
            peer_id,
            blob_sidecar,
            seen_timestamp: D,
        });
    }

    fn single_lookup_blob_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        blob_sidecar: Option<Arc<BlobSidecar<E>>>,
    ) {
        self.send_sync_message(SyncMessage::RpcBlob {
            request_id: SyncRequestId::SingleBlob { id },
            peer_id,
            blob_sidecar,
            seen_timestamp: D,
        });
    }

    fn parent_lookup_failed(&mut self, id: SingleLookupReqId, peer_id: PeerId, error: RPCError) {
        self.send_sync_message(SyncMessage::RpcError {
            peer_id,
            request_id: SyncRequestId::ParentLookup { id },
            error,
        })
    }

    fn single_lookup_failed(&mut self, id: SingleLookupReqId, peer_id: PeerId, error: RPCError) {
        self.send_sync_message(SyncMessage::RpcError {
            peer_id,
            request_id: SyncRequestId::SingleBlock { id },
            error,
        })
    }

    fn peer_disconnected(&mut self, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::Disconnect(peer_id));
    }

    fn drain_network_rx(&mut self) {
        while let Ok(event) = self.network_rx.try_recv() {
            self.network_rx_queue.push(event);
        }
    }

    fn pop_received_network_event<T, F: Fn(&NetworkMessage<E>) -> Option<T>>(
        &mut self,
        predicate_transform: F,
    ) -> Result<T, String> {
        self.drain_network_rx();

        if let Some(index) = self
            .network_rx_queue
            .iter()
            .position(|x| predicate_transform(x).is_some())
        {
            // Transform the item, knowing that it won't be None because we checked it in the position predicate.
            let transformed = predicate_transform(&self.network_rx_queue[index]).unwrap();
            self.network_rx_queue.remove(index);
            Ok(transformed)
        } else {
            Err(format!("current network messages {:?}", self.network_rx_queue).to_string())
        }
    }

    fn expect_lookup_request(&mut self, response_type: ResponseType) -> SingleLookupReqId {
        match response_type {
            ResponseType::Block => self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: Request::BlocksByRoot(_request),
                        request_id: RequestId::Sync(SyncRequestId::SingleBlock { id }),
                    } => Some(*id),
                    _ => None,
                })
                .expect("Expected block request"),
            ResponseType::Blob => self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: Request::BlobsByRoot(_request),
                        request_id: RequestId::Sync(SyncRequestId::SingleBlob { id }),
                    } => Some(*id),
                    _ => None,
                })
                .expect("Expected block request"),
        }
    }

    #[track_caller]
    fn expect_block_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(request),
                request_id: RequestId::Sync(SyncRequestId::SingleBlock { id }),
            } if request.block_roots().to_vec().contains(&for_block) => Some(*id),
            _ => None,
        })
        .expect("Expected block request")
    }

    #[track_caller]
    fn expect_blob_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlobsByRoot(request),
                request_id: RequestId::Sync(SyncRequestId::SingleBlob { id }),
            } if request
                .blob_ids
                .to_vec()
                .iter()
                .any(|r| r.block_root == for_block) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .expect("Expected blob request")
    }

    #[track_caller]
    fn expect_parent_request(&mut self, response_type: ResponseType) -> SingleLookupReqId {
        match response_type {
            ResponseType::Block => self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: Request::BlocksByRoot(_request),
                        request_id: RequestId::Sync(SyncRequestId::ParentLookup { id }),
                    } => Some(*id),
                    _ => None,
                })
                .expect("Expected block parent request"),
            ResponseType::Blob => self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: Request::BlobsByRoot(_request),
                        request_id: RequestId::Sync(SyncRequestId::ParentLookupBlob { id }),
                    } => Some(*id),
                    _ => None,
                })
                .expect("Expected blob parent request"),
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
        self.drain_network_rx();
        if !self.network_rx_queue.is_empty() {
            panic!("expected no network events: {:#?}", self.network_rx_queue);
        }
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
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::ReportPeer { .. } => Some(()),
            _ => None,
        })
        .expect("Expected peer penalty")
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
    let mut rig = TestRig::test_setup();
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let block = rig.rand_block(fork_name);
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();
    // Trigger the request
    rig.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
        peer_id, block_root,
    ));
    let id = rig.expect_lookup_request(ResponseType::Block);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    rig.single_lookup_block_response(id, peer_id, Some(block.into()));
    rig.expect_empty_network();
    rig.expect_block_process(ResponseType::Block);

    // The request should still be active.
    assert_eq!(rig.active_single_lookups_count(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    rig.single_lookup_block_response(id, peer_id, None);
    rig.single_block_component_processed(
        id,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
    );
    rig.expect_empty_network();
    assert_eq!(rig.active_single_lookups_count(), 0);
}

#[test]
fn test_single_block_lookup_empty_response() {
    let mut rig = TestRig::test_setup();
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_block(block_hash, peer_id);
    let id = rig.expect_block_lookup_request(block_hash);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_blob_lookup_request(block_hash);
    }

    // The peer does not have the block. It should be penalized.
    rig.single_lookup_block_response(id, peer_id, None);
    rig.expect_penalty();

    rig.expect_block_lookup_request(block_hash); // it should be retried
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_block(block_hash, peer_id);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // Peer sends something else. It should be penalized.
    let bad_block = rig.rand_block(fork_name);
    rig.single_lookup_block_response(id, peer_id, Some(bad_block.into()));
    rig.expect_penalty();
    rig.expect_lookup_request(response_type); // should be retried

    // Send the stream termination. This should not produce an additional penalty.
    rig.single_lookup_block_response(id, peer_id, None);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_failure() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_block(block_hash, peer_id);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    rig.single_lookup_failed(id, peer_id, RPCError::UnsupportedProtocol);
    rig.expect_lookup_request(response_type);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_becomes_parent_request() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block = Arc::new(rig.rand_block(fork_name));
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_block(block.canonical_root(), peer_id);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    rig.single_lookup_block_response(id, peer_id, Some(block.clone()));
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(rig.active_single_lookups_count(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request moved to a
    // parent request after processing.
    rig.single_block_component_processed(
        id,
        BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
    );
    assert_eq!(rig.active_single_lookups_count(), 1);
    rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }
    rig.expect_empty_network();
    assert_eq!(rig.active_parent_lookups_count(), 1);
}

#[test]
fn test_parent_lookup_happy_path() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    let id = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        chain_hash,
        BlockError::BlockIsAlreadyKnown(block_root).into(),
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    rig.parent_chain_processed(chain_hash, process_result);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_wrong_response() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the wrong block, peer should be penalized and the block re-requested.
    let bad_block = rig.rand_block(fork_name);
    rig.parent_lookup_block_response(id1, peer_id, Some(bad_block.into()));
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the stream termination for the first request. This should not produce extra penalties.
    rig.parent_lookup_block_response(id1, peer_id, None);
    rig.expect_empty_network();

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    rig.parent_chain_processed(chain_hash, process_result);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_empty_response() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends an empty response, peer should be penalized and the block re-requested.
    rig.parent_lookup_block_response(id1, peer_id, None);
    rig.expect_penalty();
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    rig.parent_chain_processed(chain_hash, process_result);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_rpc_failure() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    let id1 = rig.expect_parent_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // The request fails. It should be tried again.
    rig.parent_lookup_failed(
        id1,
        peer_id,
        RPCError::ErrorResponse(
            RPCResponseErrorCode::ResourceUnavailable,
            "older than deneb".into(),
        ),
    );
    let id2 = rig.expect_parent_request(response_type);

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(response_type);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        chain_hash,
        BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
    );
    rig.expect_parent_chain_process();
    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    rig.parent_chain_processed(chain_hash, process_result);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_too_many_attempts() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) && i == 1 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        match i % 2 {
            // make sure every error is accounted for
            0 => {
                // The request fails. It should be tried again.
                rig.parent_lookup_failed(
                    id,
                    peer_id,
                    RPCError::ErrorResponse(
                        RPCResponseErrorCode::ResourceUnavailable,
                        "older than deneb".into(),
                    ),
                );
            }
            _ => {
                // Send a bad block this time. It should be tried again.
                let bad_block = rig.rand_block(fork_name);
                rig.parent_lookup_block_response(id, peer_id, Some(bad_block.into()));
                // Send the stream termination

                // Note, previously we would send the same lookup id with a stream terminator,
                // we'd ignore it because we'd intrepret it as an unrequested response, since
                // we already got one response for the block. I'm not sure what the intent is
                // for having this stream terminator line in this test at all. Receiving an invalid
                // block and a stream terminator with the same Id now results in two failed attempts,
                // I'm unsure if this is how it should behave?
                //
                rig.parent_lookup_block_response(id, peer_id, None);
                rig.expect_penalty();
            }
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            // assert_eq!(
            //     bl.parent_lookups[0]
            //         .current_parent_request
            //         .block_request_state
            //         .state
            //         .failed_attempts(),
            //     dbg!(i)
            // );
        }
    }

    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_too_many_download_attempts_no_blacklist() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let block_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    for i in 1..=parent_lookup::PARENT_FAIL_TOLERANCE {
        assert!(!rig.failed_chains_contains(&block_hash));
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) && i == 1 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        if i % 2 != 0 {
            // The request fails. It should be tried again.
            rig.parent_lookup_failed(
                id,
                peer_id,
                RPCError::ErrorResponse(
                    RPCResponseErrorCode::ResourceUnavailable,
                    "older than deneb".into(),
                ),
            );
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block(fork_name);
            rig.parent_lookup_block_response(id, peer_id, Some(bad_block.into()));
            rig.expect_penalty();
        }
        if i < parent_lookup::PARENT_FAIL_TOLERANCE {
            // assert_eq!(
            //     bl.parent_lookups[0]
            //         .current_parent_request
            //         .block_request_state
            //         .state
            //         .failed_attempts(),
            //     dbg!(i)
            // );
        }
    }

    assert_eq!(rig.active_parent_lookups_count(), 0);
    assert!(!rig.failed_chains_contains(&block_hash));
    assert!(!rig.failed_chains_contains(&parent.canonical_root()));
}

#[test]
fn test_parent_lookup_too_many_processing_attempts_must_blacklist() {
    let response_type = ResponseType::Block;
    const PROCESSING_FAILURES: u8 = parent_lookup::PARENT_FAIL_TOLERANCE / 2 + 1;
    let mut rig = TestRig::test_setup();
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());

    let parent = Arc::new(rig.rand_block(fork_name));
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);

    // Fail downloading the block
    for i in 0..(parent_lookup::PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) && i == 0 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // The request fails. It should be tried again.
        rig.parent_lookup_failed(
            id,
            peer_id,
            RPCError::ErrorResponse(
                RPCResponseErrorCode::ResourceUnavailable,
                "older than deneb".into(),
            ),
        );
    }

    // Now fail processing a block in the parent request
    for i in 0..PROCESSING_FAILURES {
        let id = dbg!(rig.expect_parent_request(response_type));
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) && i != 0 {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        assert!(!rig.failed_chains_contains(&block_root));
        // send the right parent but fail processing
        rig.parent_lookup_block_response(id, peer_id, Some(parent.clone()));
        rig.parent_block_processed(block_root, BlockError::InvalidSignature.into());
        rig.parent_lookup_block_response(id, peer_id, None);
        rig.expect_penalty();
    }

    assert!(rig.failed_chains_contains(&block_root));
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_too_deep() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();
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

    let peer_id = rig.new_connected_peer();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    rig.search_parent(trigger_block, peer_id);

    for block in blocks.into_iter().rev() {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // the block
        rig.parent_lookup_block_response(id, peer_id, Some(block.clone()));
        // the stream termination
        rig.parent_lookup_block_response(id, peer_id, None);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        rig.parent_block_processed(
            chain_hash,
            BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
        )
    }

    rig.expect_penalty();
    assert!(rig.failed_chains_contains(&chain_hash));
}

#[test]
fn test_parent_lookup_disconnection() {
    let mut rig = TestRig::test_setup();
    let peer_id = rig.new_connected_peer();
    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let trigger_block = rig.rand_block(fork_name);
    rig.search_parent(trigger_block.into(), peer_id);

    rig.peer_disconnected(peer_id);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

#[test]
fn test_single_block_lookup_ignored_response() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let block = rig.rand_block(fork_name);
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_block(block.canonical_root(), peer_id);
    let id = rig.expect_lookup_request(response_type);
    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_lookup_request(ResponseType::Blob);
    }

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    rig.single_lookup_block_response(id, peer_id, Some(block.into()));
    rig.expect_empty_network();
    rig.expect_block_process(response_type);

    // The request should still be active.
    assert_eq!(rig.active_single_lookups_count(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request removed
    // after processing.
    rig.single_lookup_block_response(id, peer_id, None);
    // Send an Ignored response, the request should be dropped
    rig.single_block_component_processed(id, BlockProcessingResult::Ignored);
    rig.expect_empty_network();
    assert_eq!(rig.active_single_lookups_count(), 0);
}

#[test]
fn test_parent_lookup_ignored_response() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
    let parent = rig.rand_block(fork_name);
    let block = rig.block_with_parent(parent.canonical_root(), fork_name);
    let chain_hash = block.canonical_root();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.search_parent(block.into(), peer_id);
    let id = rig.expect_parent_request(response_type);

    // If we're in deneb, a blob request should have been triggered as well,
    // we don't require a response because we're generateing 0-blob blocks in this test.
    if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
        let _ = rig.expect_parent_request(ResponseType::Blob);
    }

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    rig.expect_block_process(response_type);
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    rig.parent_block_processed(chain_hash, BlockProcessingResult::Ignored);
    rig.expect_empty_network();
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

/// This is a regression test.
#[test]
fn test_same_chain_race_condition() {
    let response_type = ResponseType::Block;
    let mut rig = TestRig::test_setup();

    let fork_name = rig
        .harness
        .spec
        .fork_name_at_slot::<E>(rig.harness.chain.slot().unwrap());
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

    let peer_id = rig.new_connected_peer();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    rig.search_parent(trigger_block.clone(), peer_id);

    for (i, block) in blocks.into_iter().rev().enumerate() {
        let id = rig.expect_parent_request(response_type);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if matches!(fork_name, ForkName::Deneb | ForkName::Electra) {
            let _ = rig.expect_parent_request(ResponseType::Blob);
        }
        // the block
        rig.parent_lookup_block_response(id, peer_id, Some(block.clone()));
        // the stream termination
        rig.parent_lookup_block_response(id, peer_id, None);
        // the processing request
        rig.expect_block_process(response_type);
        // the processing result
        if i + 2 == depth {
            // one block was removed
            rig.parent_block_processed(
                chain_hash,
                BlockError::BlockIsAlreadyKnown(block.canonical_root()).into(),
            )
        } else {
            rig.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
            )
        }
        rig.assert_parent_lookups_consistency();
    }

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.expect_parent_chain_process();

    // Try to get this block again while the chain is being processed. We should not request it again.
    let peer_id = rig.new_connected_peer();
    rig.search_parent(trigger_block, peer_id);
    rig.assert_parent_lookups_consistency();

    let process_result = BatchProcessResult::Success {
        was_non_empty: true,
    };
    rig.parent_chain_processed(chain_hash, process_result);
    assert_eq!(rig.active_parent_lookups_count(), 0);
}

mod deneb_only {
    use super::*;
    use crate::sync::testing::{RpcResponse, SyncTester};
    use crate::sync::SyncMessage;
    use beacon_chain::data_availability_checker::AvailabilityCheckError;
    use lighthouse_network::types::SyncState;
    use ssz_types::VariableList;
    use std::str::FromStr;

    struct DenebTester {
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
            let mut rig = TestRig::test_setup();
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

            let peer_id = rig.new_connected_peer();

            // Trigger the request
            let (block_req_id, blob_req_id, parent_block_req_id, parent_blob_req_id) =
                match request_trigger {
                    RequestTrigger::AttestationUnknownBlock => {
                        rig.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
                            peer_id, block_root,
                        ));
                        let block_req_id = rig.expect_lookup_request(ResponseType::Block);
                        let blob_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        (Some(block_req_id), Some(blob_req_id), None, None)
                    }
                    RequestTrigger::GossipUnknownParentBlock { .. } => {
                        rig.send_sync_message(SyncMessage::UnknownParentBlock(
                            peer_id,
                            RpcBlock::new_without_blobs(Some(block_root), block.clone()),
                            block_root,
                        ));

                        let blob_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        let parent_block_req_id = rig.expect_parent_request(ResponseType::Block);
                        let parent_blob_req_id = rig.expect_parent_request(ResponseType::Blob);
                        rig.expect_empty_network(); // expect no more requests
                        (
                            None,
                            Some(blob_req_id),
                            Some(parent_block_req_id),
                            Some(parent_blob_req_id),
                        )
                    }
                    RequestTrigger::GossipUnknownParentBlob { .. } => {
                        let single_blob = blobs.first().cloned().unwrap();
                        rig.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, single_blob));

                        let block_req_id = rig.expect_lookup_request(ResponseType::Block);
                        let blobs_req_id = rig.expect_lookup_request(ResponseType::Blob);
                        let parent_block_req_id = rig.expect_parent_request(ResponseType::Block);
                        let parent_blob_req_id = rig.expect_parent_request(ResponseType::Blob);
                        rig.expect_empty_network(); // expect no more requests
                        (
                            Some(block_req_id),
                            Some(blobs_req_id),
                            Some(parent_block_req_id),
                            Some(parent_blob_req_id),
                        )
                    }
                };

            Some(Self {
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
            self.rig.parent_lookup_block_response(
                self.parent_block_req_id.expect("parent request id"),
                self.peer_id,
                Some(block),
            );

            assert_eq!(self.rig.active_parent_lookups_count(), 1);
            self
        }

        fn parent_blob_response(mut self) -> Self {
            let blobs = self.parent_blobs.pop_front().unwrap();
            let _ = self.unknown_parent_blobs.insert(blobs.clone());
            for blob in &blobs {
                self.rig.parent_lookup_blob_response(
                    self.parent_blob_req_id.expect("parent blob request id"),
                    self.peer_id,
                    Some(blob.clone()),
                );
                assert_eq!(self.rig.active_parent_lookups_count(), 1);
            }
            self.rig.parent_lookup_blob_response(
                self.parent_blob_req_id.expect("blob request id"),
                self.peer_id,
                None,
            );

            self
        }

        fn block_response_triggering_process(self) -> Self {
            let mut me = self.block_response();
            me.rig.expect_block_process(ResponseType::Block);

            // The request should still be active.
            assert_eq!(me.rig.active_single_lookups_count(), 1);
            me
        }

        fn block_response(mut self) -> Self {
            // The peer provides the correct block, should not be penalized. Now the block should be sent
            // for processing.
            self.rig.single_lookup_block_response(
                self.block_req_id.expect("block request id"),
                self.peer_id,
                Some(self.block.clone()),
            );
            self.rig.expect_empty_network();

            // The request should still be active.
            assert_eq!(self.rig.active_single_lookups_count(), 1);
            self
        }

        fn blobs_response(mut self) -> Self {
            for blob in &self.blobs {
                self.rig.single_lookup_blob_response(
                    self.blob_req_id.expect("blob request id"),
                    self.peer_id,
                    Some(blob.clone()),
                );
                assert_eq!(self.rig.active_single_lookups_count(), 1);
            }
            self.rig.single_lookup_blob_response(
                self.blob_req_id.expect("blob request id"),
                self.peer_id,
                None,
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
            self.rig.single_lookup_block_response(
                self.block_req_id.expect("block request id"),
                self.peer_id,
                None,
            );
            self
        }

        fn empty_blobs_response(mut self) -> Self {
            self.rig.single_lookup_blob_response(
                self.blob_req_id.expect("blob request id"),
                self.peer_id,
                None,
            );
            self
        }

        fn empty_parent_block_response(mut self) -> Self {
            self.rig.parent_lookup_block_response(
                self.parent_block_req_id.expect("block request id"),
                self.peer_id,
                None,
            );
            self
        }

        fn empty_parent_blobs_response(mut self) -> Self {
            self.rig.parent_lookup_blob_response(
                self.parent_blob_req_id.expect("blob request id"),
                self.peer_id,
                None,
            );
            self
        }

        fn block_imported(mut self) -> Self {
            // Missing blobs should be the request is not removed, the outstanding blobs request should
            // mean we do not send a new request.
            self.rig.single_block_component_processed(
                self.block_req_id.expect("block request id"),
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            assert_eq!(self.rig.active_single_lookups_count(), 0);
            self
        }

        fn parent_block_imported(mut self) -> Self {
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            assert_eq!(self.rig.active_parent_lookups_count(), 0);
            self
        }

        fn parent_block_unknown_parent(mut self) -> Self {
            let block = self.unknown_parent_block.take().unwrap();
            let block = RpcBlock::new(
                Some(block.canonical_root()),
                block,
                self.unknown_parent_blobs.take().map(VariableList::from),
            )
            .unwrap();
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Err(BlockError::ParentUnknown(block)),
            );
            assert_eq!(self.rig.active_parent_lookups_count(), 1);
            self
        }

        fn invalid_parent_processed(mut self) -> Self {
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Err(BlockError::ProposalSignatureInvalid),
            );
            assert_eq!(self.rig.active_parent_lookups_count(), 1);
            self
        }

        fn invalid_block_processed(mut self) -> Self {
            self.rig.single_block_component_processed(
                self.block_req_id.expect("block request id"),
                BlockProcessingResult::Err(BlockError::ProposalSignatureInvalid),
            );
            assert_eq!(self.rig.active_single_lookups_count(), 1);
            self
        }

        fn invalid_blob_processed(mut self) -> Self {
            self.rig.single_block_component_processed(
                self.blob_req_id.expect("blob request id"),
                BlockProcessingResult::Err(BlockError::AvailabilityCheck(
                    AvailabilityCheckError::KzgVerificationFailed,
                )),
            );
            assert_eq!(self.rig.active_single_lookups_count(), 1);
            self
        }

        fn missing_components_from_block_request(mut self) -> Self {
            self.rig.single_block_component_processed(
                self.block_req_id.expect("block request id"),
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    self.slot,
                    self.block_root,
                )),
            );
            assert_eq!(self.rig.active_single_lookups_count(), 1);
            self
        }

        fn missing_components_from_blob_request(mut self) -> Self {
            self.rig.single_blob_component_processed(
                self.blob_req_id.expect("blob request id"),
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    self.slot,
                    self.block_root,
                )),
            );
            assert_eq!(self.rig.active_single_lookups_count(), 1);
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
        fn expect_no_penalty_and_no_requests(mut self) -> Self {
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
        fn search_parent_dup(mut self) -> Self {
            self.rig.search_parent(self.block.clone(), self.peer_id);
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
            .expect_no_penalty_and_no_requests()
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
            .expect_no_penalty_and_no_requests();
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
            .expect_no_penalty_and_no_requests()
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
            .expect_no_penalty_and_no_requests()
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
            .expect_no_penalty_and_no_requests()
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
            .expect_no_penalty_and_no_requests()
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
            .expect_no_penalty_and_no_requests()
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

    #[test]
    fn unknown_parent_block_dup() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlock { num_parents: 1 })
        else {
            return;
        };

        tester
            .search_parent_dup()
            .expect_no_blobs_request()
            .expect_no_block_request();
    }

    #[test]
    fn unknown_parent_blob_dup() {
        let Some(tester) =
            DenebTester::new(RequestTrigger::GossipUnknownParentBlob { num_parents: 1 })
        else {
            return;
        };

        tester
            .search_parent_dup()
            .expect_no_blobs_request()
            .expect_no_block_request();
    }

    #[tokio::test]
    async fn no_peer_penalty_when_rpc_response_already_known_from_gossip() {
        let fork_name = ForkName::Deneb;
        let mut sync_tester = SyncTester::new(&fork_name);

        let (block_chain, blobs_chain) = sync_tester.create_block_chain(&fork_name, 2);
        let block = block_chain.front().unwrap();
        let block_root = block.canonical_root();
        let rpc_block = RpcBlock::new_without_blobs(Some(block_root), block.clone());
        let peer_id = PeerId::random();

        sync_tester
            .set_node_sync_state(SyncState::Synced)
            .add_connected_peer(&peer_id)
            // GIVEN a current lookup of a block is triggered via `UnknownParentBlock`
            .send_sync_messages(vec![SyncMessage::UnknownParentBlock(
                peer_id, rpc_block, block_root,
            )])
            .expect_rpc_request("current_lookup_req_id", |msg| {
                if let NetworkMessage::SendRequest {
                    request: Request::BlobsByRoot(request),
                    ..
                } = msg
                {
                    request
                        .blob_ids
                        .as_slice()
                        .iter()
                        .any(|blob_id| blob_id.block_root == block_root)
                } else {
                    false
                }
            })
            .await
            // A peer responds with blob 0
            .send_rpc_response(
                "current_lookup_req_id",
                RpcResponse::Blob(
                    peer_id,
                    Some(blobs_chain.front().unwrap().first().unwrap().clone()),
                ),
            )
            // Blob 1 is received via gossip, triggers `UnknownParentBlob`
            .send_sync_messages(vec![SyncMessage::UnknownParentBlob(
                peer_id,
                blobs_chain.front().unwrap().get(1).unwrap().clone(),
            )])
            // A peer responds with blob 1 (same as gossip blob above)
            .send_rpc_response(
                "current_lookup_req_id",
                RpcResponse::Blob(
                    peer_id,
                    Some(blobs_chain.front().unwrap().get(1).unwrap().clone()),
                ),
            )
            // Assert peer isn't penalised
            .expect_no_penalty()
            .await;
    }
}
