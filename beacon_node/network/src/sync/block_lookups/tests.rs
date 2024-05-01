use crate::network_beacon_processor::NetworkBeaconProcessor;

use crate::service::RequestId;
use crate::sync::manager::{
    BlockProcessType, RequestId as SyncRequestId, SingleLookupReqId, SyncManager,
};
use crate::sync::SyncMessage;
use crate::NetworkMessage;
use std::sync::Arc;

use super::*;

use crate::sync::block_lookups::common::{ResponseType, PARENT_DEPTH_TOLERANCE};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::builder::Witness;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::{
    build_log, generate_rand_block_and_blobs, BeaconChainHarness, EphemeralHarnessType, NumBlobs,
};
use beacon_processor::WorkEvent;
use lighthouse_network::rpc::{RPCError, RPCResponseErrorCode};
use lighthouse_network::types::SyncState;
use lighthouse_network::{NetworkGlobals, Request};
use slog::info;
use slot_clock::{ManualSlotClock, SlotClock, TestingSlotClock};
use store::MemoryStore;
use tokio::sync::mpsc;
use types::{
    test_utils::{SeedableRng, XorShiftRng},
    BlobSidecar, ForkName, MinimalEthSpec as E, SignedBeaconBlock, Slot,
};

type T = Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

/// This test utility enables integration testing of Lighthouse sync components.
///
/// It covers the following:
/// 1. Sending `SyncMessage` to `SyncManager` to trigger `RangeSync`, `BackFillSync` and `BlockLookups` behaviours.
/// 2. Making assertions on `WorkEvent`s received from sync
/// 3. Making assertion on `NetworkMessage` received from sync (Outgoing RPC requests).
///
/// The test utility covers testing the interactions from and to `SyncManager`. In diagram form:
///                      +-----------------+
///                      | BeaconProcessor |
///                      +---------+-------+
///                             ^  |
///                             |  |
///                   WorkEvent |  | SyncMsg
///                             |  | (Result)
///                             |  v
/// +--------+            +-----+-----------+             +----------------+
/// | Router +----------->|  SyncManager    +------------>| NetworkService |
/// +--------+  SyncMsg   +-----------------+ NetworkMsg  +----------------+
///           (RPC resp)  |  - RangeSync    |  (RPC req)
///                       +-----------------+
///                       |  - BackFillSync |
///                       +-----------------+
///                       |  - BlockLookups |
///                       +-----------------+
struct TestRig {
    /// Receiver for `BeaconProcessor` events (e.g. block processing results).
    beacon_processor_rx: mpsc::Receiver<WorkEvent<E>>,
    /// Receiver for `NetworkMessage` (e.g. outgoing RPC requests from sync)
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Stores all `NetworkMessage`s received from `network_recv`. (e.g. outgoing RPC requests)
    network_rx_queue: Vec<NetworkMessage<E>>,
    /// To send `SyncMessage`. For sending RPC responses or block processing results to sync.
    sync_manager: SyncManager<T>,
    /// To manipulate sync state and peer connection status
    network_globals: Arc<NetworkGlobals<E>>,
    /// `rng` for generating test blocks and blobs.
    rng: XorShiftRng,
    fork_name: ForkName,
    log: Logger,
}

const D: Duration = Duration::new(0, 0);
const PARENT_FAIL_TOLERANCE: u8 = SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;

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

        let fork_name = chain.spec.fork_name_at_slot::<E>(chain.slot().unwrap());

        // All current tests expect synced and EL online state
        beacon_processor
            .network_globals
            .set_sync_state(SyncState::Synced);

        let rng = XorShiftRng::from_seed([42; 16]);
        TestRig {
            beacon_processor_rx,
            network_rx,
            network_rx_queue: vec![],
            rng,
            network_globals: beacon_processor.network_globals.clone(),
            sync_manager: SyncManager::new(
                chain,
                network_tx,
                beacon_processor.into(),
                sync_recv,
                log.clone(),
            ),
            fork_name,
            log,
        }
    }

    fn test_setup_after_deneb() -> Option<Self> {
        let r = Self::test_setup();
        if r.after_deneb() {
            Some(r)
        } else {
            None
        }
    }

    fn log(&self, msg: &str) {
        info!(self.log, "TEST_RIG"; "msg" => msg);
    }

    fn after_deneb(&self) -> bool {
        matches!(self.fork_name, ForkName::Deneb | ForkName::Electra)
    }

    fn trigger_unknown_parent_block(&mut self, peer_id: PeerId, block: Arc<SignedBeaconBlock<E>>) {
        let block_root = block.canonical_root();
        self.send_sync_message(SyncMessage::UnknownParentBlock(
            peer_id,
            RpcBlock::new_without_blobs(Some(block_root), block),
            block_root,
        ))
    }

    fn trigger_unknown_parent_blob(&mut self, peer_id: PeerId, blob: BlobSidecar<E>) {
        self.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, blob.into()));
    }

    fn trigger_unknown_block_from_attestation(&mut self, block_root: Hash256, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
            peer_id, block_root,
        ));
    }

    fn rand_block(&mut self) -> SignedBeaconBlock<E> {
        self.rand_block_and_blobs(NumBlobs::None).0
    }

    fn rand_block_and_blobs(
        &mut self,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let fork_name = self.fork_name;
        let rng = &mut self.rng;
        generate_rand_block_and_blobs::<E>(fork_name, num_blobs, rng)
    }

    pub fn rand_block_and_parent(
        &mut self,
    ) -> (SignedBeaconBlock<E>, SignedBeaconBlock<E>, Hash256, Hash256) {
        let parent = self.rand_block();
        let parent_root = parent.canonical_root();
        let mut block = self.rand_block();
        *block.message_mut().parent_root_mut() = parent_root;
        let block_root = block.canonical_root();
        (parent, block, parent_root, block_root)
    }

    fn send_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.handle_message(sync_message);
    }

    fn active_single_lookups(&self) -> Vec<(Id, Hash256, Option<Hash256>)> {
        self.sync_manager.active_single_lookups()
    }

    fn active_single_lookups_count(&self) -> usize {
        self.sync_manager.active_single_lookups().len()
    }

    fn active_parent_lookups(&self) -> Vec<Vec<Hash256>> {
        self.sync_manager.active_parent_lookups()
    }

    fn active_parent_lookups_count(&self) -> usize {
        self.sync_manager.active_parent_lookups().len()
    }

    fn assert_single_lookups_count(&self, count: usize) {
        assert_eq!(
            self.active_single_lookups_count(),
            count,
            "Unexpected count of single lookups. Current lookups: {:?}",
            self.active_single_lookups()
        );
    }

    fn assert_parent_lookups_count(&self, count: usize) {
        assert_eq!(
            self.active_parent_lookups_count(),
            count,
            "Unexpected count of parent lookups. Parent lookups: {:?}. Current lookups: {:?}",
            self.active_parent_lookups(),
            self.active_single_lookups()
        );
    }

    fn assert_lookup_is_active(&self, block_root: Hash256) {
        let lookups = self.sync_manager.active_single_lookups();
        if !lookups.iter().any(|l| l.1 == block_root) {
            panic!("Expected lookup {block_root} to be the only active: {lookups:?}");
        }
    }

    fn insert_failed_chain(&mut self, block_root: Hash256) {
        self.sync_manager.insert_failed_chain(block_root);
    }

    fn assert_not_failed_chain(&mut self, chain_hash: Hash256) {
        let failed_chains = self.sync_manager.get_failed_chains();
        if failed_chains.contains(&chain_hash) {
            panic!("failed chains contain {chain_hash:?}: {failed_chains:?}");
        }
    }

    fn failed_chains_contains(&mut self, chain_hash: &Hash256) -> bool {
        self.sync_manager.get_failed_chains().contains(chain_hash)
    }

    fn find_single_lookup_for(&self, block_root: Hash256) -> Id {
        self.active_single_lookups()
            .iter()
            .find(|(_, b, _)| b == &block_root)
            .unwrap_or_else(|| panic!("no single block lookup found for {block_root}"))
            .0
    }

    fn expect_no_active_single_lookups(&self) {
        assert!(
            self.active_single_lookups().is_empty(),
            "expect no single block lookups: {:?}",
            self.active_single_lookups()
        );
    }

    fn expect_no_active_lookups(&self) {
        self.expect_no_active_single_lookups();
    }

    fn expect_lookups(&self, expected_block_roots: &[Hash256]) {
        let block_roots = self
            .active_single_lookups()
            .iter()
            .map(|(_, b, _)| *b)
            .collect::<Vec<_>>();
        assert_eq!(&block_roots, expected_block_roots);
    }

    fn new_connected_peer(&mut self) -> PeerId {
        let peer_id = PeerId::random();
        self.network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(&peer_id);
        peer_id
    }

    fn parent_chain_processed_success(
        &mut self,
        chain_hash: Hash256,
        blocks: &[Arc<SignedBeaconBlock<E>>],
    ) {
        // Send import events for all pending parent blocks
        for _ in blocks {
            self.parent_block_processed_imported(chain_hash);
        }
        // Send final import event for the block that triggered the lookup
        self.single_block_component_processed_imported(chain_hash);
    }

    /// Locate a parent lookup chain with tip hash `chain_hash`
    fn find_oldest_parent_lookup(&self, chain_hash: Hash256) -> Hash256 {
        let parent_chain = self
            .active_parent_lookups()
            .into_iter()
            .find(|chain| chain.first() == Some(&chain_hash))
            .unwrap_or_else(|| {
                panic!(
                    "No parent chain with chain_hash {chain_hash:?}: Parent lookups {:?} Single lookups {:?}",
                    self.active_parent_lookups(),
                    self.active_single_lookups(),
                )
            });
        *parent_chain.last().unwrap()
    }

    fn parent_block_processed(&mut self, chain_hash: Hash256, result: BlockProcessingResult<E>) {
        let id = self.find_single_lookup_for(self.find_oldest_parent_lookup(chain_hash));
        self.single_block_component_processed(id, result);
    }

    fn parent_blob_processed(&mut self, chain_hash: Hash256, result: BlockProcessingResult<E>) {
        let id = self.find_single_lookup_for(self.find_oldest_parent_lookup(chain_hash));
        self.single_blob_component_processed(id, result);
    }

    fn parent_block_processed_imported(&mut self, chain_hash: Hash256) {
        self.parent_block_processed(
            chain_hash,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(chain_hash)),
        );
    }

    fn single_block_component_processed(&mut self, id: Id, result: BlockProcessingResult<E>) {
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::SingleBlock { id },
            result,
        })
    }

    fn single_block_component_processed_imported(&mut self, block_root: Hash256) {
        let id = self.find_single_lookup_for(block_root);
        self.single_block_component_processed(
            id,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root)),
        )
    }

    fn single_blob_component_processed(&mut self, id: Id, result: BlockProcessingResult<E>) {
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::SingleBlob { id },
            result,
        })
    }

    fn parent_lookup_block_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        beacon_block: Option<Arc<SignedBeaconBlock<E>>>,
    ) {
        self.log("parent_lookup_block_response");
        self.send_sync_message(SyncMessage::RpcBlock {
            request_id: SyncRequestId::SingleBlock { id },
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
        self.log("single_lookup_block_response");
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
        self.log(&format!(
            "parent_lookup_blob_response {:?}",
            blob_sidecar.as_ref().map(|b| b.index)
        ));
        self.send_sync_message(SyncMessage::RpcBlob {
            request_id: SyncRequestId::SingleBlob { id },
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
            request_id: SyncRequestId::SingleBlock { id },
            error,
        })
    }

    fn parent_lookup_failed_unavailable(&mut self, id: SingleLookupReqId, peer_id: PeerId) {
        self.parent_lookup_failed(
            id,
            peer_id,
            RPCError::ErrorResponse(
                RPCResponseErrorCode::ResourceUnavailable,
                "older than deneb".into(),
            ),
        );
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
        .unwrap_or_else(|e| panic!("Expected block request for {for_block:?}: {e}"))
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
        .unwrap_or_else(|e| panic!("Expected blob request for {for_block:?}: {e}"))
    }

    #[track_caller]
    fn expect_block_parent_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(request),
                request_id: RequestId::Sync(SyncRequestId::SingleBlock { id }),
            } if request.block_roots().to_vec().contains(&for_block) => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected block parent request for {for_block:?}: {e}"))
    }

    #[track_caller]
    fn expect_blob_parent_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlobsByRoot(request),
                request_id: RequestId::Sync(SyncRequestId::SingleBlob { id }),
            } if request
                .blob_ids
                .to_vec()
                .iter()
                .all(|r| r.block_root == for_block) =>
            {
                Some(*id)
            }
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected blob parent request for {for_block:?}: {e}"))
    }

    fn expect_lookup_request_block_and_blobs(&mut self, block_root: Hash256) -> SingleLookupReqId {
        let id = self.expect_block_lookup_request(block_root);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if self.after_deneb() {
            let _ = self.expect_blob_lookup_request(block_root);
        }
        id
    }

    fn expect_parent_request_block_and_blobs(&mut self, block_root: Hash256) -> SingleLookupReqId {
        let id = self.expect_block_parent_request(block_root);
        // If we're in deneb, a blob request should have been triggered as well,
        // we don't require a response because we're generateing 0-blob blocks in this test.
        if self.after_deneb() {
            let _ = self.expect_blob_parent_request(block_root);
        }
        id
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

    fn expect_no_penalty_for(&mut self, peer_id: PeerId) {
        self.drain_network_rx();
        let downscore_events = self
            .network_rx_queue
            .iter()
            .filter_map(|ev| match ev {
                NetworkMessage::ReportPeer {
                    peer_id: p_id, msg, ..
                } if p_id == &peer_id => Some(msg),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !downscore_events.is_empty() {
            panic!("Some downscore events for {peer_id}: {downscore_events:?}");
        }
    }

    #[track_caller]
    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                // Parent chain sends blocks one by one
                assert_eq!(work.work_type(), beacon_processor::RPC_BLOCK);
            }
            other => panic!(
                "Expected rpc_block from chain segment process, found {:?}",
                other
            ),
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
        match self.beacon_processor_rx.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {} // ok
            Ok(event) => panic!("expected empty beacon processor: {:?}", event),
            other => panic!("unexpected err {:?}", other),
        }
    }

    #[track_caller]
    pub fn expect_penalty(&mut self, peer_id: PeerId, expect_penalty_msg: &'static str) {
        let penalty_msg = self
            .pop_received_network_event(|ev| match ev {
                NetworkMessage::ReportPeer {
                    peer_id: p_id, msg, ..
                } if p_id == &peer_id => Some(msg.to_owned()),
                _ => None,
            })
            .unwrap_or_else(|_| {
                panic!(
                    "Expected '{expect_penalty_msg}' penalty for peer {peer_id}: {:#?}",
                    self.network_rx_queue
                )
            });
        assert_eq!(
            penalty_msg, expect_penalty_msg,
            "Unexpected penalty msg for {peer_id}"
        );
    }

    pub fn expect_single_penalty(&mut self, peer_id: PeerId, expect_penalty_msg: &'static str) {
        self.expect_penalty(peer_id, expect_penalty_msg);
        self.expect_no_penalty_for(peer_id);
    }

    pub fn block_with_parent_and_blobs(
        &mut self,
        parent_root: Hash256,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let (mut block, mut blobs) = self.rand_block_and_blobs(num_blobs);
        *block.message_mut().parent_root_mut() = parent_root;
        blobs.iter_mut().for_each(|blob| {
            blob.signed_block_header = block.signed_block_header();
        });
        (block, blobs)
    }

    pub fn rand_blockchain(&mut self, depth: usize) -> Vec<Arc<SignedBeaconBlock<E>>> {
        let mut blocks = Vec::<Arc<SignedBeaconBlock<E>>>::with_capacity(depth);
        for slot in 0..depth {
            let parent = blocks
                .last()
                .map(|b| b.canonical_root())
                .unwrap_or_else(Hash256::random);
            let mut block = self.rand_block();
            *block.message_mut().parent_root_mut() = parent;
            *block.message_mut().slot_mut() = slot.into();
            blocks.push(block.into());
        }
        self.log(&format!(
            "Blockchain dump {:#?}",
            blocks
                .iter()
                .map(|b| format!(
                    "block {} {} parent {}",
                    b.slot(),
                    b.canonical_root(),
                    b.parent_root()
                ))
                .collect::<Vec<_>>()
        ));
        blocks
    }
}

#[test]
fn stable_rng() {
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let (block, _) = generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng);
    assert_eq!(
        block.canonical_root(),
        Hash256::from_slice(
            &hex::decode("adfd2e9e7a7976e8ccaed6eaf0257ed36a5b476732fee63ff44966602fd099ec")
                .unwrap()
        ),
        "rng produces a consistent value"
    );
}

#[test]
fn test_single_block_lookup_happy_path() {
    let mut rig = TestRig::test_setup();
    let block = rig.rand_block();
    let peer_id = rig.new_connected_peer();
    let block_root = block.canonical_root();
    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block_root);

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
    rig.single_block_component_processed_imported(block_root);
    rig.expect_empty_network();
    rig.expect_no_active_lookups();
}

#[test]
fn test_single_block_lookup_empty_response() {
    let mut rig = TestRig::test_setup();

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block_hash, peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block_hash);

    // The peer does not have the block. It should be penalized.
    rig.single_lookup_block_response(id, peer_id, None);
    rig.expect_penalty(peer_id, "NoResponseReturned");

    rig.expect_block_lookup_request(block_hash); // it should be retried
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let mut rig = TestRig::test_setup();

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block_hash, peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block_hash);

    // Peer sends something else. It should be penalized.
    let bad_block = rig.rand_block();
    rig.single_lookup_block_response(id, peer_id, Some(bad_block.into()));
    rig.expect_penalty(peer_id, "UnrequestedBlockRoot");
    rig.expect_block_lookup_request(block_hash); // should be retried

    // Send the stream termination. This should not produce an additional penalty.
    rig.single_lookup_block_response(id, peer_id, None);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_failure() {
    let mut rig = TestRig::test_setup();

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block_hash, peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block_hash);

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    rig.single_lookup_failed(id, peer_id, RPCError::UnsupportedProtocol);
    rig.expect_block_lookup_request(block_hash);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_becomes_parent_request() {
    let mut rig = TestRig::test_setup();

    let block = Arc::new(rig.rand_block());
    let block_root = block.canonical_root();
    let parent_root = block.parent_root();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block.canonical_root(), peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block_root);

    // The peer provides the correct block, should not be penalized. Now the block should be sent
    // for processing.
    rig.single_lookup_block_response(id, peer_id, Some(block.clone()));
    rig.expect_empty_network();
    rig.expect_block_process(ResponseType::Block);

    // The request should still be active.
    assert_eq!(rig.active_single_lookups_count(), 1);

    // Send the stream termination. Peer should have not been penalized, and the request moved to a
    // parent request after processing.
    rig.single_block_component_processed(
        id.lookup_id,
        BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
    );
    assert_eq!(rig.active_single_lookups_count(), 2); // 2 = current + parent
    rig.expect_parent_request_block_and_blobs(parent_root);
    rig.expect_empty_network();
    assert_eq!(rig.active_parent_lookups_count(), 1);
}

#[test]
fn test_parent_lookup_happy_path() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id = rig.expect_parent_request_block_and_blobs(parent_root);

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        block_root,
        BlockError::BlockIsAlreadyKnown(block_root).into(),
    );
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_wrong_response() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id1 = rig.expect_parent_request_block_and_blobs(parent_root);

    // Peer sends the wrong block, peer should be penalized and the block re-requested.
    let bad_block = rig.rand_block();
    rig.parent_lookup_block_response(id1, peer_id, Some(bad_block.into()));
    rig.expect_penalty(peer_id, "UnrequestedBlockRoot");
    let id2 = rig.expect_block_parent_request(parent_root);

    // Send the stream termination for the first request. This should not produce extra penalties.
    rig.parent_lookup_block_response(id1, peer_id, None);
    rig.expect_empty_network();

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed_imported(block_root);
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_empty_response() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id1 = rig.expect_parent_request_block_and_blobs(parent_root);

    // Peer sends an empty response, peer should be penalized and the block re-requested.
    rig.parent_lookup_block_response(id1, peer_id, None);
    rig.expect_penalty(peer_id, "NoResponseReturned");
    let id2 = rig.expect_block_parent_request(parent_root);

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed_imported(block_root);

    rig.single_block_component_processed_imported(block_root);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_rpc_failure() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id1 = rig.expect_parent_request_block_and_blobs(parent_root);

    // The request fails. It should be tried again.
    rig.parent_lookup_failed_unavailable(id1, peer_id);
    let id2 = rig.expect_block_parent_request(parent_root);

    // Send the right block this time.
    rig.parent_lookup_block_response(id2, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);

    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed_imported(block_root);
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_too_many_attempts() {
    let mut rig = TestRig::test_setup();

    let block = rig.rand_block();
    let parent_root = block.parent_root();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    for i in 1..=PARENT_FAIL_TOLERANCE {
        let id = rig.expect_block_parent_request(parent_root);
        // Blobs are only requested in the first iteration as this test only retries blocks
        if rig.after_deneb() && i == 1 {
            let _ = rig.expect_blob_parent_request(parent_root);
        }

        if i % 2 == 0 {
            // make sure every error is accounted for
            // The request fails. It should be tried again.
            rig.parent_lookup_failed_unavailable(id, peer_id);
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block();
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
            rig.expect_penalty(peer_id, "UnrequestedBlockRoot");
        }
    }

    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_too_many_download_attempts_no_blacklist() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    for i in 1..=PARENT_FAIL_TOLERANCE {
        assert!(!rig.failed_chains_contains(&block_root));
        let id = rig.expect_block_parent_request(parent_root);
        // Blobs are only requested in the first iteration as this test only retries blocks
        if rig.after_deneb() && i == 1 {
            let _ = rig.expect_blob_parent_request(parent_root);
        }
        if i % 2 != 0 {
            // The request fails. It should be tried again.
            rig.parent_lookup_failed_unavailable(id, peer_id);
        } else {
            // Send a bad block this time. It should be tried again.
            let bad_block = rig.rand_block();
            rig.parent_lookup_block_response(id, peer_id, Some(bad_block.into()));
            rig.expect_penalty(peer_id, "UnrequestedBlockRoot");
        }
    }

    assert!(!rig.failed_chains_contains(&block_root));
    assert!(!rig.failed_chains_contains(&parent.canonical_root()));
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_too_many_processing_attempts_must_blacklist() {
    const PROCESSING_FAILURES: u8 = PARENT_FAIL_TOLERANCE / 2 + 1;
    let mut rig = TestRig::test_setup();
    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());

    rig.log("Fail downloading the block");
    for i in 0..(PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_block_parent_request(parent_root);
        // Blobs are only requested in the first iteration as this test only retries blocks
        if rig.after_deneb() && i == 0 {
            let _ = rig.expect_blob_parent_request(parent_root);
        }
        // The request fails. It should be tried again.
        rig.parent_lookup_failed_unavailable(id, peer_id);
    }

    rig.log("Now fail processing a block in the parent request");
    for _ in 0..PROCESSING_FAILURES {
        let id = rig.expect_block_parent_request(parent_root);
        // Blobs are only requested in the previous first iteration as this test only retries blocks
        rig.assert_not_failed_chain(block_root);
        // send the right parent but fail processing
        rig.parent_lookup_block_response(id, peer_id, Some(parent.clone().into()));
        rig.parent_block_processed(block_root, BlockError::InvalidSignature.into());
        rig.parent_lookup_block_response(id, peer_id, None);
        rig.expect_penalty(peer_id, "lookup_block_processing_failure");
    }

    rig.assert_not_failed_chain(block_root);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_too_deep() {
    let mut rig = TestRig::test_setup();
    let mut blocks = rig.rand_blockchain(PARENT_DEPTH_TOLERANCE);

    let peer_id = rig.new_connected_peer();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    rig.trigger_unknown_parent_block(peer_id, trigger_block);

    for block in blocks.into_iter().rev() {
        let id = rig.expect_parent_request_block_and_blobs(block.canonical_root());
        // the block
        rig.parent_lookup_block_response(id, peer_id, Some(block.clone()));
        // the stream termination
        rig.parent_lookup_block_response(id, peer_id, None);
        // the processing request
        rig.expect_block_process(ResponseType::Block);
        // the processing result
        rig.parent_block_processed(
            chain_hash,
            BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
        )
    }

    rig.expect_penalty(peer_id, "chain_too_long");
    assert!(rig.failed_chains_contains(&chain_hash));
}

#[test]
fn test_parent_lookup_disconnection_no_peers_left() {
    let mut rig = TestRig::test_setup();
    let peer_id = rig.new_connected_peer();
    let trigger_block = rig.rand_block();
    rig.trigger_unknown_parent_block(peer_id, trigger_block.into());

    rig.peer_disconnected(peer_id);
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_disconnection_peer_left() {
    let mut rig = TestRig::test_setup();
    let peer_ids = (0..2).map(|_| rig.new_connected_peer()).collect::<Vec<_>>();
    let trigger_block = rig.rand_block();
    // lookup should have two peers associated with the same block
    for peer_id in peer_ids.iter() {
        rig.trigger_unknown_parent_block(*peer_id, trigger_block.clone().into());
    }
    // Disconnect the first peer only, which is the one handling the request
    rig.peer_disconnected(*peer_ids.first().unwrap());
    rig.assert_parent_lookups_count(1);
}

#[test]
fn test_skip_creating_failed_parent_lookup() {
    let mut rig = TestRig::test_setup();
    let (_, block, parent_root, _) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();
    rig.insert_failed_chain(parent_root);
    rig.trigger_unknown_parent_block(peer_id, block.into());
    // Expect single penalty for peer, despite dropping two lookups
    rig.expect_single_penalty(peer_id, "failed_chain");
    // Both current and parent lookup should be rejected
    rig.expect_no_active_lookups();
}

#[test]
fn test_skip_creating_failed_current_lookup() {
    let mut rig = TestRig::test_setup();
    let (_, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();
    rig.insert_failed_chain(block_root);
    rig.trigger_unknown_parent_block(peer_id, block.into());
    // Expect single penalty for peer
    rig.expect_single_penalty(peer_id, "failed_chain");
    // Only the current lookup should be rejected
    rig.expect_lookups(&[parent_root]);
}

#[test]
fn test_single_block_lookup_ignored_response() {
    let mut rig = TestRig::test_setup();

    let block = rig.rand_block();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block.canonical_root(), peer_id);
    let id = rig.expect_lookup_request_block_and_blobs(block.canonical_root());

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
    // Send an Ignored response, the request should be dropped
    rig.single_block_component_processed(id.lookup_id, BlockProcessingResult::Ignored);
    rig.expect_empty_network();
    rig.expect_no_active_lookups();
}

#[test]
fn test_parent_lookup_ignored_response() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.clone().into());
    let id = rig.expect_parent_request_block_and_blobs(parent_root);
    // Note: single block lookup for current `block` does not trigger any request because it does
    // not have blobs, and the block is already cached

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);
    rig.expect_empty_network();

    // Return an Ignored result. The request should be dropped
    rig.parent_block_processed(block_root, BlockProcessingResult::Ignored);
    rig.expect_empty_network();
    rig.expect_no_active_lookups();
}

/// This is a regression test.
#[test]
fn test_same_chain_race_condition() {
    let mut rig = TestRig::test_setup();

    // if we use one or two blocks it will match on the hash or the parent hash, so make a longer
    // chain.
    let depth = 4;
    let mut blocks = rig.rand_blockchain(depth);
    let peer_id = rig.new_connected_peer();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    rig.trigger_unknown_parent_block(peer_id, trigger_block.clone());

    for (i, block) in blocks.clone().into_iter().rev().enumerate() {
        let id = rig.expect_parent_request_block_and_blobs(block.canonical_root());
        // the block
        rig.parent_lookup_block_response(id, peer_id, Some(block.clone()));
        // the stream termination
        rig.parent_lookup_block_response(id, peer_id, None);
        // the processing request
        rig.expect_block_process(ResponseType::Block);
        // the processing result
        if i + 2 == depth {
            rig.log(&format!("Block {i} was removed and is already known"));
            rig.parent_block_processed(
                chain_hash,
                BlockError::BlockIsAlreadyKnown(block.canonical_root()).into(),
            )
        } else {
            rig.log(&format!("Block {i} ParentUnknown"));
            rig.parent_block_processed(
                chain_hash,
                BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
            )
        }
    }

    // Try to get this block again while the chain is being processed. We should not request it again.
    let peer_id = rig.new_connected_peer();
    rig.trigger_unknown_parent_block(peer_id, trigger_block.clone());
    rig.expect_empty_network();

    // Processing succeeds, now the rest of the chain should be sent for processing.
    for block in blocks.iter().skip(1).chain(&[trigger_block]) {
        rig.expect_parent_chain_process();
        rig.single_block_component_processed_imported(block.canonical_root());
    }
    rig.expect_no_active_lookups();
}

mod deneb_only {
    use super::*;
    use beacon_chain::{
        block_verification_types::RpcBlock, data_availability_checker::AvailabilityCheckError,
    };
    use ssz_types::VariableList;
    use std::collections::VecDeque;

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
            let Some(mut rig) = TestRig::test_setup_after_deneb() else {
                return None;
            };
            let (block, blobs) = rig.rand_block_and_blobs(NumBlobs::Random);
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
                    rig.block_with_parent_and_blobs(parent_root, NumBlobs::Random);
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
                        let block_req_id = rig.expect_block_lookup_request(block_root);
                        let blob_req_id = rig.expect_blob_lookup_request(block_root);
                        (Some(block_req_id), Some(blob_req_id), None, None)
                    }
                    RequestTrigger::GossipUnknownParentBlock { .. } => {
                        rig.send_sync_message(SyncMessage::UnknownParentBlock(
                            peer_id,
                            RpcBlock::new_without_blobs(Some(block_root), block.clone()),
                            block_root,
                        ));

                        let parent_root = block.parent_root();
                        let blob_req_id = rig.expect_blob_lookup_request(block_root);
                        let parent_block_req_id = rig.expect_block_parent_request(parent_root);
                        let parent_blob_req_id = rig.expect_blob_parent_request(parent_root);
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
                        let parent_root = single_blob.block_parent_root();
                        rig.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, single_blob));

                        let block_req_id = rig.expect_block_lookup_request(block_root);
                        let blobs_req_id = rig.expect_blob_lookup_request(block_root);
                        let parent_block_req_id = rig.expect_block_parent_request(parent_root);
                        let parent_blob_req_id = rig.expect_blob_parent_request(parent_root);
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

        fn log(self, msg: &str) -> Self {
            self.rig.log(msg);
            self
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

            self.rig.assert_parent_lookups_count(1);
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
            self.rig
                .assert_lookup_is_active(self.block.canonical_root());
            self
        }

        fn blobs_response(mut self) -> Self {
            self.rig
                .log(&format!("blobs response {}", self.blobs.len()));
            for blob in &self.blobs {
                self.rig.single_lookup_blob_response(
                    self.blob_req_id.expect("blob request id"),
                    self.peer_id,
                    Some(blob.clone()),
                );
                self.rig
                    .assert_lookup_is_active(self.block.canonical_root());
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

        fn block_missing_components(mut self) -> Self {
            self.rig.single_block_component_processed(
                self.block_req_id.expect("block request id").lookup_id,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    self.block.slot(),
                    self.block_root,
                )),
            );
            self.rig.expect_empty_network();
            self.rig.assert_single_lookups_count(1);
            self
        }

        fn blob_imported(mut self) -> Self {
            self.rig.single_blob_component_processed(
                self.blob_req_id.expect("blob request id").lookup_id,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            self.rig.assert_single_lookups_count(0);
            self
        }

        fn block_imported(mut self) -> Self {
            // Missing blobs should be the request is not removed, the outstanding blobs request should
            // mean we do not send a new request.
            self.rig.single_block_component_processed(
                self.block_req_id
                    .or(self.blob_req_id)
                    .expect("block request id")
                    .lookup_id,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            self.rig.assert_single_lookups_count(0);
            self
        }

        fn parent_block_imported(mut self) -> Self {
            self.rig.log("parent_block_imported");
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            self.rig.assert_parent_lookups_count(0);
            self
        }

        fn parent_blob_imported(mut self) -> Self {
            self.rig.log("parent_blob_imported");
            self.rig.parent_blob_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(self.block_root)),
            );
            self.rig.expect_empty_network();
            self.rig.assert_parent_lookups_count(0);
            self
        }

        fn parent_block_unknown_parent(mut self) -> Self {
            self.rig.log("parent_block_unknown_parent");
            let block = self.unknown_parent_block.take().unwrap();
            // Now this block is the one we expect requests from
            self.block = block.clone();
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

        fn parent_block_missing_components(mut self) -> Self {
            let block = self.unknown_parent_block.clone().unwrap();
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    block.slot(),
                    block.canonical_root(),
                )),
            );
            self.rig.parent_blob_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    block.slot(),
                    block.canonical_root(),
                )),
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
                self.block_req_id.expect("block request id").lookup_id,
                BlockProcessingResult::Err(BlockError::ProposalSignatureInvalid),
            );
            self.rig.assert_single_lookups_count(1);
            self
        }

        fn invalid_blob_processed(mut self) -> Self {
            self.rig.log("invalid_blob_processed");
            self.rig.single_blob_component_processed(
                self.blob_req_id.expect("blob request id").lookup_id,
                BlockProcessingResult::Err(BlockError::AvailabilityCheck(
                    AvailabilityCheckError::KzgVerificationFailed,
                )),
            );
            self.rig.assert_single_lookups_count(1);
            self
        }

        fn missing_components_from_block_request(mut self) -> Self {
            self.rig.single_block_component_processed(
                self.block_req_id.expect("block request id").lookup_id,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    self.slot,
                    self.block_root,
                )),
            );
            self.rig.assert_single_lookups_count(1);
            self
        }

        fn missing_components_from_blob_request(mut self) -> Self {
            self.rig.single_blob_component_processed(
                self.blob_req_id.expect("blob request id").lookup_id,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    self.slot,
                    self.block_root,
                )),
            );
            self.rig.assert_single_lookups_count(1);
            self
        }

        fn expect_penalty(mut self, expect_penalty_msg: &'static str) -> Self {
            self.rig.expect_penalty(self.peer_id, expect_penalty_msg);
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
            let id = self
                .rig
                .expect_block_lookup_request(self.block.canonical_root());
            self.block_req_id = Some(id);
            self
        }
        fn expect_blobs_request(mut self) -> Self {
            let id = self
                .rig
                .expect_blob_lookup_request(self.block.canonical_root());
            self.blob_req_id = Some(id);
            self
        }
        fn expect_parent_block_request(mut self) -> Self {
            let id = self
                .rig
                .expect_block_parent_request(self.block.parent_root());
            self.parent_block_req_id = Some(id);
            self
        }
        fn expect_parent_blobs_request(mut self) -> Self {
            let id = self
                .rig
                .expect_blob_parent_request(self.block.parent_root());
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
        fn expect_no_active_lookups(self) -> Self {
            self.rig.expect_no_active_lookups();
            self
        }
        fn search_parent_dup(mut self) -> Self {
            self.rig
                .trigger_unknown_parent_block(self.peer_id, self.block.clone());
            self
        }
    }

    #[test]
    fn single_block_and_blob_lookup_block_returned_first_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .block_response_triggering_process()
            .blobs_response()
            .block_missing_components() // blobs not yet imported
            .blobs_response_was_valid()
            .blob_imported(); // now blobs resolve as imported
    }

    #[test]
    fn single_block_and_blob_lookup_blobs_returned_first_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .blobs_response() // hold blobs for processing
            .block_response_triggering_process()
            .block_missing_components() // blobs not yet imported
            .blobs_response_was_valid()
            .blob_imported(); // now blobs resolve as imported
    }

    #[test]
    fn single_block_and_blob_lookup_empty_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };

        tester
            .empty_block_response()
            .expect_penalty("NoResponseReturned")
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
            .expect_penalty("sent_incomplete_blobs")
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
            .expect_no_penalty_and_no_requests()
            // blobs not sent for processing until the block is processed
            .empty_block_response()
            .expect_penalty("NoResponseReturned")
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
            .expect_penalty("lookup_block_processing_failure")
            .expect_block_request()
            .expect_no_blobs_request()
            .blobs_response()
            // blobs not sent for processing until the block is processed
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
            .expect_penalty("lookup_blobs_processing_failure")
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
            .expect_penalty("sent_incomplete_blobs")
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
            .expect_penalty("DuplicateData")
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
            .blobs_response() // blobs are not sent until the block is processed
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
            .expect_penalty("DuplicateData")
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
            .expect_penalty("lookup_block_processing_failure")
            .expect_parent_block_request()
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
            .expect_penalty("NoResponseReturned")
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
            .log(" Return empty blobs for parent, block errors with missing components, downscore")
            .empty_parent_blobs_response()
            .expect_no_penalty_and_no_requests()
            .parent_block_response()
            .parent_block_missing_components()
            .expect_penalty("sent_incomplete_blobs")
            .log("Re-request parent blobs, succeed and import parent")
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .parent_blob_imported()
            .log("resolve original block trigger blobs request and import")
            .block_imported()
            .expect_no_active_lookups();
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
            .expect_penalty("lookup_block_processing_failure")
            .expect_parent_block_request()
            // blobs are not sent until block is processed
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
            .blobs_response()
            .expect_parent_chain_process()
            .block_imported()
            .expect_no_active_lookups();
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
            .blobs_response()
            .expect_parent_chain_process()
            .block_imported()
            .expect_no_active_lookups();
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
            .expect_penalty("NoResponseReturned")
            .expect_parent_block_request()
            .expect_no_blobs_request()
            .parent_blob_response()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .expect_block_process()
            .parent_block_imported()
            .blobs_response()
            .block_response()
            .block_imported()
            .expect_no_active_lookups();
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
            .log(" Return empty blobs for parent, block errors with missing components, downscore")
            .empty_parent_blobs_response()
            .expect_no_penalty_and_no_requests()
            .parent_block_response()
            .parent_block_missing_components()
            .expect_penalty("sent_incomplete_blobs")
            .log("Re-request parent blobs, succeed and import parent")
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .parent_blob_imported()
            .log("resolve original block trigger blobs request and import")
            .blobs_response()
            .block_imported()
            .expect_no_active_lookups();
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

    #[test]
    fn no_peer_penalty_when_rpc_response_already_known_from_gossip() {
        let Some(mut r) = TestRig::test_setup_after_deneb() else {
            return;
        };
        let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(2));
        let block_root = block.canonical_root();
        let blob_0 = blobs[0].clone();
        let blob_1 = blobs[1].clone();
        let peer_a = r.new_connected_peer();
        let peer_b = r.new_connected_peer();
        // Send unknown parent block lookup
        r.trigger_unknown_parent_block(peer_a, block.into());
        // Expect network request for blobs
        let id = r.expect_blob_lookup_request(block_root);
        // Peer responses with blob 0
        r.single_lookup_blob_response(id, peer_a, Some(blob_0.into()));
        // Blob 1 is received via gossip unknown parent blob from a different peer
        r.trigger_unknown_parent_blob(peer_b, blob_1.clone());
        // Original peer sends blob 1 via RPC
        r.single_lookup_blob_response(id, peer_a, Some(blob_1.into()));
        // Assert no downscore event for original peer
        r.expect_no_penalty_for(peer_a);
    }
}
