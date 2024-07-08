use crate::network_beacon_processor::NetworkBeaconProcessor;

use crate::sync::manager::{BlockProcessType, SyncManager};
use crate::sync::SyncMessage;
use crate::NetworkMessage;
use std::sync::Arc;

use super::*;

use crate::sync::block_lookups::common::ResponseType;
use beacon_chain::blob_verification::GossipVerifiedBlob;
use beacon_chain::block_verification_types::{BlockImportData, RpcBlock};
use beacon_chain::builder::Witness;
use beacon_chain::data_availability_checker::Availability;
use beacon_chain::eth1_chain::CachingEth1Backend;
use beacon_chain::test_utils::{
    build_log, generate_rand_block_and_blobs, BeaconChainHarness, EphemeralHarnessType, NumBlobs,
};
use beacon_chain::{
    AvailabilityPendingExecutedBlock, PayloadVerificationOutcome, PayloadVerificationStatus,
};
use beacon_processor::WorkEvent;
use lighthouse_network::rpc::{RPCError, RPCResponseErrorCode};
use lighthouse_network::service::api_types::{AppRequestId, Id, SingleLookupReqId, SyncRequestId};
use lighthouse_network::types::SyncState;
use lighthouse_network::{NetworkGlobals, Request};
use slog::info;
use slot_clock::{ManualSlotClock, SlotClock, TestingSlotClock};
use store::MemoryStore;
use tokio::sync::mpsc;
use types::test_utils::TestRandom;
use types::{
    test_utils::{SeedableRng, XorShiftRng},
    BlobSidecar, ForkName, MinimalEthSpec as E, SignedBeaconBlock, Slot,
};
use types::{BeaconState, BeaconStateBase};

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
    beacon_processor_rx_queue: Vec<WorkEvent<E>>,
    /// Receiver for `NetworkMessage` (e.g. outgoing RPC requests from sync)
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    /// Stores all `NetworkMessage`s received from `network_recv`. (e.g. outgoing RPC requests)
    network_rx_queue: Vec<NetworkMessage<E>>,
    /// To send `SyncMessage`. For sending RPC responses or block processing results to sync.
    sync_manager: SyncManager<T>,
    /// To manipulate sync state and peer connection status
    network_globals: Arc<NetworkGlobals<E>>,
    /// Beacon chain harness
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
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
            beacon_processor_rx_queue: vec![],
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
            harness,
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

    fn active_single_lookups(&self) -> Vec<BlockLookupSummary> {
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

    fn assert_lookup_peers(&self, block_root: Hash256, mut expected_peers: Vec<PeerId>) {
        let mut lookup = self
            .sync_manager
            .active_single_lookups()
            .into_iter()
            .find(|l| l.1 == block_root)
            .unwrap_or_else(|| panic!("no lookup for {block_root}"));
        lookup.3.sort();
        expected_peers.sort();
        assert_eq!(
            lookup.3, expected_peers,
            "unexpected peers on lookup {block_root}"
        );
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

    fn assert_failed_chain(&mut self, chain_hash: Hash256) {
        let failed_chains = self.sync_manager.get_failed_chains();
        if !failed_chains.contains(&chain_hash) {
            panic!("expected failed chains to contain {chain_hash:?}: {failed_chains:?}");
        }
    }

    fn find_single_lookup_for(&self, block_root: Hash256) -> Id {
        self.active_single_lookups()
            .iter()
            .find(|l| l.1 == block_root)
            .unwrap_or_else(|| panic!("no single block lookup found for {block_root}"))
            .0
    }

    #[track_caller]
    fn expect_no_active_single_lookups(&self) {
        assert!(
            self.active_single_lookups().is_empty(),
            "expect no single block lookups: {:?}",
            self.active_single_lookups()
        );
    }

    #[track_caller]
    fn expect_no_active_lookups(&self) {
        self.expect_no_active_single_lookups();
    }

    fn expect_no_active_lookups_empty_network(&mut self) {
        self.expect_no_active_lookups();
        self.expect_empty_network();
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

    fn complete_single_lookup_blob_download(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        blobs: Vec<BlobSidecar<E>>,
    ) {
        for blob in blobs {
            self.single_lookup_blob_response(id, peer_id, Some(blob.into()));
        }
        self.single_lookup_blob_response(id, peer_id, None);
    }

    fn complete_single_lookup_blob_lookup_valid(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        blobs: Vec<BlobSidecar<E>>,
        import: bool,
    ) {
        let block_root = blobs.first().unwrap().block_root();
        let block_slot = blobs.first().unwrap().slot();
        self.complete_single_lookup_blob_download(id, peer_id, blobs);
        self.expect_block_process(ResponseType::Blob);
        self.single_blob_component_processed(
            id.lookup_id,
            if import {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root))
            } else {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    block_slot, block_root,
                ))
            },
        );
    }

    fn complete_lookup_block_download(&mut self, block: SignedBeaconBlock<E>) {
        let block_root = block.canonical_root();
        let id = self.expect_block_lookup_request(block_root);
        self.expect_empty_network();
        let peer_id = self.new_connected_peer();
        self.single_lookup_block_response(id, peer_id, Some(block.into()));
        self.single_lookup_block_response(id, peer_id, None);
    }

    fn complete_lookup_block_import_valid(&mut self, block_root: Hash256, import: bool) {
        self.expect_block_process(ResponseType::Block);
        let id = self.find_single_lookup_for(block_root);
        self.single_block_component_processed(
            id,
            if import {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root))
            } else {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    Slot::new(0),
                    block_root,
                ))
            },
        )
    }

    fn complete_single_lookup_block_valid(&mut self, block: SignedBeaconBlock<E>, import: bool) {
        let block_root = block.canonical_root();
        self.complete_lookup_block_download(block);
        self.complete_lookup_block_import_valid(block_root, import)
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

    /// Return RPCErrors for all active requests of peer
    fn rpc_error_all_active_requests(&mut self, disconnected_peer_id: PeerId) {
        self.drain_network_rx();
        while let Ok(request_id) = self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request_id: AppRequestId::Sync(id),
                ..
            } if *peer_id == disconnected_peer_id => Some(*id),
            _ => None,
        }) {
            self.send_sync_message(SyncMessage::RpcError {
                peer_id: disconnected_peer_id,
                request_id,
                error: RPCError::Disconnected,
            });
        }
    }

    fn peer_disconnected(&mut self, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::Disconnect(peer_id));
    }

    fn drain_network_rx(&mut self) {
        while let Ok(event) = self.network_rx.try_recv() {
            self.network_rx_queue.push(event);
        }
    }

    fn drain_processor_rx(&mut self) {
        while let Ok(event) = self.beacon_processor_rx.try_recv() {
            self.beacon_processor_rx_queue.push(event);
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

    fn pop_received_processor_event<T, F: Fn(&WorkEvent<E>) -> Option<T>>(
        &mut self,
        predicate_transform: F,
    ) -> Result<T, String> {
        self.drain_processor_rx();

        if let Some(index) = self
            .beacon_processor_rx_queue
            .iter()
            .position(|x| predicate_transform(x).is_some())
        {
            // Transform the item, knowing that it won't be None because we checked it in the position predicate.
            let transformed = predicate_transform(&self.beacon_processor_rx_queue[index]).unwrap();
            self.beacon_processor_rx_queue.remove(index);
            Ok(transformed)
        } else {
            Err(format!(
                "current processor messages {:?}",
                self.beacon_processor_rx_queue
            )
            .to_string())
        }
    }

    fn find_block_lookup_request(
        &mut self,
        for_block: Hash256,
    ) -> Result<SingleLookupReqId, String> {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(request),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
            } if request.block_roots().to_vec().contains(&for_block) => Some(*id),
            _ => None,
        })
    }

    #[track_caller]
    fn expect_block_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.find_block_lookup_request(for_block)
            .unwrap_or_else(|e| panic!("Expected block request for {for_block:?}: {e}"))
    }

    fn find_blob_lookup_request(
        &mut self,
        for_block: Hash256,
    ) -> Result<SingleLookupReqId, String> {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlobsByRoot(request),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
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
    }

    #[track_caller]
    fn expect_blob_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.find_blob_lookup_request(for_block)
            .unwrap_or_else(|e| panic!("Expected blob request for {for_block:?}: {e}"))
    }

    #[track_caller]
    fn expect_block_parent_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlocksByRoot(request),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
            } if request.block_roots().to_vec().contains(&for_block) => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|e| panic!("Expected block parent request for {for_block:?}: {e}"))
    }

    fn expect_no_requests_for(&mut self, block_root: Hash256) {
        if let Ok(request) = self.find_block_lookup_request(block_root) {
            panic!("Expected no block request for {block_root:?} found {request:?}");
        }
        if let Ok(request) = self.find_blob_lookup_request(block_root) {
            panic!("Expected no blob request for {block_root:?} found {request:?}");
        }
    }

    #[track_caller]
    fn expect_blob_parent_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: Request::BlobsByRoot(request),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
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

    #[track_caller]
    fn expect_block_process(&mut self, response_type: ResponseType) {
        match response_type {
            ResponseType::Block => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::RPC_BLOCK).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected block work event: {e}")),
            ResponseType::Blob => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::RPC_BLOBS).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected blobs work event: {e}")),
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

    fn insert_block_to_da_checker(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        let state = BeaconState::Base(BeaconStateBase::random_for_test(&mut self.rng));
        let parent_block = self.rand_block();
        let import_data = BlockImportData::<E>::__new_for_test(
            block.canonical_root(),
            state,
            parent_block.into(),
        );
        let payload_verification_outcome = PayloadVerificationOutcome {
            payload_verification_status: PayloadVerificationStatus::Verified,
            is_valid_merge_transition_block: false,
        };
        let executed_block =
            AvailabilityPendingExecutedBlock::new(block, import_data, payload_verification_outcome);
        match self
            .harness
            .chain
            .data_availability_checker
            .put_pending_executed_block(executed_block)
            .unwrap()
        {
            Availability::Available(_) => panic!("block removed from da_checker, available"),
            Availability::MissingComponents(block_root) => {
                self.log(&format!("inserted block to da_checker {block_root:?}"))
            }
        };
    }

    fn insert_blob_to_da_checker(&mut self, blob: BlobSidecar<E>) {
        match self
            .harness
            .chain
            .data_availability_checker
            .put_gossip_blob(GossipVerifiedBlob::__assumed_valid(blob.into()))
            .unwrap()
        {
            Availability::Available(_) => panic!("blob removed from da_checker, available"),
            Availability::MissingComponents(block_root) => {
                self.log(&format!("inserted blob to da_checker {block_root:?}"))
            }
        };
    }

    fn insert_block_to_processing_cache(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.harness
            .chain
            .reqresp_pre_import_cache
            .write()
            .insert(block.canonical_root(), block);
    }

    fn simulate_block_gossip_processing_becomes_invalid(&mut self, block_root: Hash256) {
        self.harness
            .chain
            .reqresp_pre_import_cache
            .write()
            .remove(&block_root);

        self.send_sync_message(SyncMessage::GossipBlockProcessResult {
            block_root,
            imported: false,
        });
    }

    fn simulate_block_gossip_processing_becomes_valid_missing_components(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) {
        let block_root = block.canonical_root();
        self.harness
            .chain
            .reqresp_pre_import_cache
            .write()
            .remove(&block_root);

        self.insert_block_to_da_checker(block);

        self.send_sync_message(SyncMessage::GossipBlockProcessResult {
            block_root,
            imported: false,
        });
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
    let id = rig.expect_block_lookup_request(block_root);

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

// Tests that if a peer does not respond with a block, we downscore and retry the block only
#[test]
fn test_single_block_lookup_empty_response() {
    let mut r = TestRig::test_setup();

    let block = r.rand_block();
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();

    // Trigger the request
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    let id = r.expect_block_lookup_request(block_root);

    // The peer does not have the block. It should be penalized.
    r.single_lookup_block_response(id, peer_id, None);
    r.expect_penalty(peer_id, "NoResponseReturned");
    // it should be retried
    let id = r.expect_block_lookup_request(block_root);
    // Send the right block this time.
    r.single_lookup_block_response(id, peer_id, Some(block.into()));
    r.expect_block_process(ResponseType::Block);
    r.single_block_component_processed_imported(block_root);
    r.expect_no_active_lookups();
}

#[test]
fn test_single_block_lookup_wrong_response() {
    let mut rig = TestRig::test_setup();

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block_hash, peer_id);
    let id = rig.expect_block_lookup_request(block_hash);

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
    let id = rig.expect_block_lookup_request(block_hash);

    // The request fails. RPC failures are handled elsewhere so we should not penalize the peer.
    rig.single_lookup_failed(id, peer_id, RPCError::UnsupportedProtocol);
    rig.expect_block_lookup_request(block_hash);
    rig.expect_empty_network();
}

#[test]
fn test_single_block_lookup_peer_disconnected_then_rpc_error() {
    let mut rig = TestRig::test_setup();

    let block_hash = Hash256::random();
    let peer_id = rig.new_connected_peer();

    // Trigger the request.
    rig.trigger_unknown_block_from_attestation(block_hash, peer_id);
    let id = rig.expect_block_lookup_request(block_hash);

    // The peer disconnect event reaches sync before the rpc error.
    rig.peer_disconnected(peer_id);
    // The lookup is not removed as it can still potentially make progress.
    rig.assert_single_lookups_count(1);
    // The request fails.
    rig.single_lookup_failed(id, peer_id, RPCError::Disconnected);
    rig.expect_block_lookup_request(block_hash);
    // The request should be removed from the network context on disconnection.
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
    let id = rig.expect_block_parent_request(block_root);

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
    rig.expect_block_parent_request(parent_root);
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
    let id = rig.expect_block_parent_request(parent_root);

    // Peer sends the right block, it should be sent for processing. Peer should not be penalized.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    // No request of blobs because the block has not data
    rig.expect_empty_network();
    rig.expect_block_process(ResponseType::Block);
    rig.expect_empty_network();

    // Add peer to child lookup to prevent it being dropped
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed(
        block_root,
        BlockError::BlockIsAlreadyKnown(block_root).into(),
    );
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn test_parent_lookup_wrong_response() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id1 = rig.expect_block_parent_request(parent_root);

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

    // Add peer to child lookup to prevent it being dropped
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed_imported(block_root);
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn test_parent_lookup_rpc_failure() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    let id = rig.expect_block_parent_request(parent_root);

    // The request fails. It should be tried again.
    rig.parent_lookup_failed_unavailable(id, peer_id);
    let id = rig.expect_block_parent_request(parent_root);

    // Send the right block this time.
    rig.parent_lookup_block_response(id, peer_id, Some(parent.into()));
    rig.expect_block_process(ResponseType::Block);

    // Add peer to child lookup to prevent it being dropped
    rig.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Processing succeeds, now the rest of the chain should be sent for processing.
    rig.parent_block_processed_imported(block_root);
    rig.expect_parent_chain_process();
    rig.parent_chain_processed_success(block_root, &[]);
    rig.expect_no_active_lookups_empty_network();
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

    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn test_parent_lookup_too_many_download_attempts_no_blacklist() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.into());
    for i in 1..=PARENT_FAIL_TOLERANCE {
        rig.assert_not_failed_chain(block_root);
        let id = rig.expect_block_parent_request(parent_root);
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

    rig.assert_not_failed_chain(block_root);
    rig.assert_not_failed_chain(parent.canonical_root());
    rig.expect_no_active_lookups_empty_network();
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
    for _ in 0..(PARENT_FAIL_TOLERANCE - PROCESSING_FAILURES) {
        let id = rig.expect_block_parent_request(parent_root);
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
    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn test_parent_lookup_too_deep_grow_ancestor() {
    let mut rig = TestRig::test_setup();
    let mut blocks = rig.rand_blockchain(PARENT_DEPTH_TOLERANCE);

    let peer_id = rig.new_connected_peer();
    let trigger_block = blocks.pop().unwrap();
    let chain_hash = trigger_block.canonical_root();
    rig.trigger_unknown_parent_block(peer_id, trigger_block);

    for block in blocks.into_iter().rev() {
        let id = rig.expect_block_parent_request(block.canonical_root());
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
    rig.assert_failed_chain(chain_hash);
}

#[test]
fn test_parent_lookup_too_deep_grow_tip() {
    let mut rig = TestRig::test_setup();
    let blocks = rig.rand_blockchain(PARENT_DEPTH_TOLERANCE - 1);
    let peer_id = rig.new_connected_peer();
    let tip = blocks.last().unwrap().clone();

    for block in blocks.into_iter() {
        let block_root = block.canonical_root();
        rig.trigger_unknown_block_from_attestation(block_root, peer_id);
        let id = rig.expect_block_parent_request(block_root);
        rig.single_lookup_block_response(id, peer_id, Some(block.clone()));
        rig.single_lookup_block_response(id, peer_id, None);
        rig.expect_block_process(ResponseType::Block);
        rig.single_block_component_processed(
            id.lookup_id,
            BlockError::ParentUnknown(RpcBlock::new_without_blobs(None, block)).into(),
        );
    }

    rig.expect_penalty(peer_id, "chain_too_long");
    rig.assert_failed_chain(tip.canonical_root());
}

#[test]
fn test_lookup_peer_disconnected_no_peers_left_while_request() {
    let mut rig = TestRig::test_setup();
    let peer_id = rig.new_connected_peer();
    let trigger_block = rig.rand_block();
    rig.trigger_unknown_parent_block(peer_id, trigger_block.into());
    rig.peer_disconnected(peer_id);
    rig.rpc_error_all_active_requests(peer_id);
    // Erroring all rpc requests and disconnecting the peer shouldn't remove the requests
    // from the lookups map as they can still progress.
    rig.assert_single_lookups_count(2);
}

#[test]
fn test_lookup_disconnection_peer_left() {
    let mut rig = TestRig::test_setup();
    let peer_ids = (0..2).map(|_| rig.new_connected_peer()).collect::<Vec<_>>();
    let disconnecting_peer = *peer_ids.first().unwrap();
    let block_root = Hash256::random();
    // lookup should have two peers associated with the same block
    for peer_id in peer_ids.iter() {
        rig.trigger_unknown_block_from_attestation(block_root, *peer_id);
    }
    // Disconnect the first peer only, which is the one handling the request
    rig.peer_disconnected(disconnecting_peer);
    rig.rpc_error_all_active_requests(disconnecting_peer);
    rig.assert_single_lookups_count(1);
}

#[test]
fn test_lookup_add_peers_to_parent() {
    let mut r = TestRig::test_setup();
    let peer_id_1 = r.new_connected_peer();
    let peer_id_2 = r.new_connected_peer();
    let blocks = r.rand_blockchain(5);
    let last_block_root = blocks.last().unwrap().canonical_root();
    // Create a chain of lookups
    for block in &blocks {
        r.trigger_unknown_parent_block(peer_id_1, block.clone());
    }
    r.trigger_unknown_block_from_attestation(last_block_root, peer_id_2);
    for block in blocks.iter().take(blocks.len() - 1) {
        // Parent has the original unknown parent event peer + new peer
        r.assert_lookup_peers(block.canonical_root(), vec![peer_id_1, peer_id_2]);
    }
    // Child lookup only has the unknown attestation peer
    r.assert_lookup_peers(last_block_root, vec![peer_id_2]);
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
fn test_single_block_lookup_ignored_response() {
    let mut rig = TestRig::test_setup();

    let block = rig.rand_block();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_block_from_attestation(block.canonical_root(), peer_id);
    let id = rig.expect_block_lookup_request(block.canonical_root());

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
    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn test_parent_lookup_ignored_response() {
    let mut rig = TestRig::test_setup();

    let (parent, block, parent_root, block_root) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();

    // Trigger the request
    rig.trigger_unknown_parent_block(peer_id, block.clone().into());
    let id = rig.expect_block_parent_request(parent_root);
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
        let id = rig.expect_block_parent_request(block.canonical_root());
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

    // Add a peer to the tip child lookup which has zero peers
    rig.trigger_unknown_block_from_attestation(trigger_block.canonical_root(), peer_id);

    rig.log("Processing succeeds, now the rest of the chain should be sent for processing.");
    for block in blocks.iter().skip(1).chain(&[trigger_block]) {
        rig.expect_parent_chain_process();
        rig.single_block_component_processed_imported(block.canonical_root());
    }
    rig.expect_no_active_lookups_empty_network();
}

#[test]
fn block_in_da_checker_skips_download() {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.insert_block_to_da_checker(block.into());
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Should not trigger block request
    let id = r.expect_blob_lookup_request(block_root);
    r.expect_empty_network();
    // Resolve blob and expect lookup completed
    r.complete_single_lookup_blob_lookup_valid(id, peer_id, blobs, true);
    r.expect_no_active_lookups();
}

#[test]
fn block_in_processing_cache_becomes_invalid() {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.insert_block_to_processing_cache(block.clone().into());
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Should trigger blob request
    let id = r.expect_blob_lookup_request(block_root);
    // Should not trigger block request
    r.expect_empty_network();
    // Simulate invalid block, removing it from processing cache
    r.simulate_block_gossip_processing_becomes_invalid(block_root);
    // Should download block, then issue blobs request
    r.complete_lookup_block_download(block);
    // Should not trigger block or blob request
    r.expect_empty_network();
    r.complete_lookup_block_import_valid(block_root, false);
    // Resolve blob and expect lookup completed
    r.complete_single_lookup_blob_lookup_valid(id, peer_id, blobs, true);
    r.expect_no_active_lookups();
}

#[test]
fn block_in_processing_cache_becomes_valid_imported() {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.insert_block_to_processing_cache(block.clone().into());
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Should trigger blob request
    let id = r.expect_blob_lookup_request(block_root);
    // Should not trigger block request
    r.expect_empty_network();
    // Resolve the block from processing step
    r.simulate_block_gossip_processing_becomes_valid_missing_components(block.into());
    // Should not trigger block or blob request
    r.expect_empty_network();
    // Resolve blob and expect lookup completed
    r.complete_single_lookup_blob_lookup_valid(id, peer_id, blobs, true);
    r.expect_no_active_lookups();
}

// IGNORE: wait for change that delays blob fetching to knowing the block
#[ignore]
#[test]
fn blobs_in_da_checker_skip_download() {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    for blob in blobs {
        r.insert_blob_to_da_checker(blob);
    }
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Should download and process the block
    r.complete_single_lookup_block_valid(block, true);
    // Should not trigger blob request
    r.expect_empty_network();
    r.expect_no_active_lookups();
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
        parent_block_roots: Vec<Hash256>,
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
        GossipUnknownParentBlock(usize),
        GossipUnknownParentBlob(usize),
    }

    impl RequestTrigger {
        fn num_parents(&self) -> usize {
            match self {
                RequestTrigger::AttestationUnknownBlock => 0,
                RequestTrigger::GossipUnknownParentBlock(num_parents) => *num_parents,
                RequestTrigger::GossipUnknownParentBlob(num_parents) => *num_parents,
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
            let mut parent_block_roots = vec![];
            for _ in 0..num_parents {
                // Set the current  block as the parent.
                let parent_root = block.canonical_root();
                let parent_block = block.clone();
                let parent_blobs = blobs.clone();
                parent_block_chain.push_front(parent_block);
                parent_blobs_chain.push_front(parent_blobs);
                parent_block_roots.push(parent_root);

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
                        (Some(block_req_id), None, None, None)
                    }
                    RequestTrigger::GossipUnknownParentBlock { .. } => {
                        rig.send_sync_message(SyncMessage::UnknownParentBlock(
                            peer_id,
                            RpcBlock::new_without_blobs(Some(block_root), block.clone()),
                            block_root,
                        ));

                        let parent_root = block.parent_root();
                        let parent_block_req_id = rig.expect_block_parent_request(parent_root);
                        rig.expect_empty_network(); // expect no more requests
                        (None, None, Some(parent_block_req_id), None)
                    }
                    RequestTrigger::GossipUnknownParentBlob { .. } => {
                        let single_blob = blobs.first().cloned().unwrap();
                        let parent_root = single_blob.block_parent_root();
                        rig.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, single_blob));

                        let parent_block_req_id = rig.expect_block_parent_request(parent_root);
                        rig.expect_empty_network(); // expect no more requests
                        (None, None, Some(parent_block_req_id), None)
                    }
                };

            Some(Self {
                rig,
                block,
                blobs,
                parent_block: parent_block_chain,
                parent_blobs: parent_blobs_chain,
                parent_block_roots,
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

        fn trigger_unknown_block_from_attestation(mut self) -> Self {
            let block_root = self.block.canonical_root();
            self.rig
                .trigger_unknown_block_from_attestation(block_root, self.peer_id);
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

        fn parent_block_response_expect_blobs(mut self) -> Self {
            self.rig.expect_empty_network();
            let block = self.parent_block.pop_front().unwrap().clone();
            let _ = self.unknown_parent_block.insert(block.clone());
            self.rig.parent_lookup_block_response(
                self.parent_block_req_id.expect("parent request id"),
                self.peer_id,
                Some(block),
            );

            // Expect blobs request after sending block
            let s = self.expect_parent_blobs_request();

            s.rig.assert_parent_lookups_count(1);
            s
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
                self.parent_blob_req_id.expect("parent blob request id"),
                self.peer_id,
                None,
            );

            self
        }

        fn block_response_triggering_process(self) -> Self {
            let mut me = self.block_response_and_expect_blob_request();
            me.rig.expect_block_process(ResponseType::Block);

            // The request should still be active.
            assert_eq!(me.rig.active_single_lookups_count(), 1);
            me
        }

        fn block_response_and_expect_blob_request(mut self) -> Self {
            // The peer provides the correct block, should not be penalized. Now the block should be sent
            // for processing.
            self.rig.single_lookup_block_response(
                self.block_req_id.expect("block request id"),
                self.peer_id,
                Some(self.block.clone()),
            );
            // After responding with block the node will issue a blob request
            let mut s = self.expect_blobs_request();

            s.rig.expect_empty_network();

            // The request should still be active.
            s.rig.assert_lookup_is_active(s.block.canonical_root());
            s
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
            let parent_root = *self.parent_block_roots.first().unwrap();
            self.rig
                .log(&format!("parent_block_imported {parent_root:?}"));
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(parent_root)),
            );
            self.rig.expect_no_requests_for(parent_root);
            self.rig.assert_parent_lookups_count(0);
            self
        }

        fn parent_block_missing_components(mut self) -> Self {
            let parent_root = *self.parent_block_roots.first().unwrap();
            self.rig
                .log(&format!("parent_block_missing_components {parent_root:?}"));
            self.rig.parent_block_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    Slot::new(0),
                    parent_root,
                )),
            );
            self.rig.expect_no_requests_for(parent_root);
            self
        }

        fn parent_blob_imported(mut self) -> Self {
            let parent_root = *self.parent_block_roots.first().unwrap();
            self.rig
                .log(&format!("parent_blob_imported {parent_root:?}"));
            self.rig.parent_blob_processed(
                self.block_root,
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(parent_root)),
            );

            self.rig.expect_no_requests_for(parent_root);
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
            // Add block to da_checker so blobs request can continue
            self.rig.insert_block_to_da_checker(self.block.clone());

            self.rig.assert_single_lookups_count(1);
            self
        }

        fn complete_current_block_and_blobs_lookup(self) -> Self {
            self.expect_block_request()
                .block_response_and_expect_blob_request()
                .blobs_response()
                // TODO: Should send blobs for processing
                .expect_block_process()
                .block_imported()
        }

        fn parent_block_then_empty_parent_blobs(self) -> Self {
            self.log(
                " Return empty blobs for parent, block errors with missing components, downscore",
            )
            .parent_block_response()
            .expect_parent_blobs_request()
            .empty_parent_blobs_response()
            .expect_penalty("NotEnoughResponsesReturned")
            .log("Re-request parent blobs, succeed and import parent")
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_missing_components()
            // Insert new peer into child request before completing parent
            .trigger_unknown_block_from_attestation()
            .parent_blob_imported()
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
            .block_response_and_expect_blob_request()
            .blobs_response()
            .block_missing_components() // blobs not yet imported
            .blobs_response_was_valid()
            .blob_imported(); // now blobs resolve as imported
    }

    #[test]
    fn single_block_response_then_empty_blob_response_attestation() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };
        tester
            .block_response_and_expect_blob_request()
            .missing_components_from_block_request()
            .empty_blobs_response()
            .expect_penalty("NotEnoughResponsesReturned")
            .expect_blobs_request()
            .expect_no_block_request();
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
            .expect_penalty("NotEnoughResponsesReturned")
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
            .expect_penalty("TooManyResponses")
            // Network context returns "download success" because the request has enough blobs + it
            // downscores the peer for returning too many.
            .expect_no_block_request();
    }

    // Test peer returning block that has unknown parent, and a new lookup is created
    #[test]
    fn parent_block_unknown_parent() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlock(1)) else {
            return;
        };
        tester
            .expect_empty_beacon_processor()
            .parent_block_response_expect_blobs()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_empty_beacon_processor();
    }

    // Test peer returning invalid (processing) block, expect retry
    #[test]
    fn parent_block_invalid_parent() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlock(1)) else {
            return;
        };
        tester
            .parent_block_response_expect_blobs()
            .parent_blob_response()
            .expect_block_process()
            .invalid_parent_processed()
            .expect_penalty("lookup_block_processing_failure")
            .expect_parent_block_request()
            .expect_empty_beacon_processor();
    }

    // Tests that if a peer does not respond with a block, we downscore and retry the block only
    #[test]
    fn empty_block_is_retried() {
        let Some(tester) = DenebTester::new(RequestTrigger::AttestationUnknownBlock) else {
            return;
        };
        tester
            .empty_block_response()
            .expect_penalty("NoResponseReturned")
            .expect_block_request()
            .expect_no_blobs_request()
            .block_response_and_expect_blob_request()
            .blobs_response()
            .block_imported()
            .expect_no_active_lookups();
    }

    #[test]
    fn parent_block_then_empty_parent_blobs() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlock(1)) else {
            return;
        };
        tester
            .parent_block_then_empty_parent_blobs()
            .log("resolve original block trigger blobs request and import")
            // Should not have block request, it is cached
            .expect_blobs_request()
            // TODO: Should send blobs for processing
            .block_imported()
            .expect_no_active_lookups();
    }

    #[test]
    fn parent_blob_unknown_parent() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(1)) else {
            return;
        };
        tester
            .expect_empty_beacon_processor()
            .parent_block_response_expect_blobs()
            .parent_blob_response()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_empty_beacon_processor();
    }

    #[test]
    fn parent_blob_invalid_parent() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(1)) else {
            return;
        };
        tester
            .expect_empty_beacon_processor()
            .parent_block_response_expect_blobs()
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
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(1)) else {
            return;
        };
        tester
            .parent_block_response()
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_block_process()
            .trigger_unknown_block_from_attestation()
            .parent_block_imported()
            .complete_current_block_and_blobs_lookup()
            .expect_no_active_lookups();
    }

    #[test]
    fn parent_block_then_empty_parent_blobs_blob_trigger() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(1)) else {
            return;
        };
        tester
            .parent_block_then_empty_parent_blobs()
            .log("resolve original block trigger blobs request and import")
            .complete_current_block_and_blobs_lookup()
            .expect_no_active_lookups();
    }

    #[test]
    fn parent_blob_unknown_parent_chain() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(2)) else {
            return;
        };
        tester
            .expect_empty_beacon_processor()
            .parent_block_response_expect_blobs()
            .parent_blob_response()
            .expect_no_penalty()
            .expect_block_process()
            .parent_block_unknown_parent()
            .expect_parent_block_request()
            .expect_empty_beacon_processor()
            .parent_block_response()
            .expect_parent_blobs_request()
            .parent_blob_response()
            .expect_no_penalty()
            .expect_block_process();
    }

    #[test]
    fn unknown_parent_block_dup() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlock(1)) else {
            return;
        };
        tester
            .search_parent_dup()
            .expect_no_blobs_request()
            .expect_no_block_request();
    }

    #[test]
    fn unknown_parent_blob_dup() {
        let Some(tester) = DenebTester::new(RequestTrigger::GossipUnknownParentBlob(1)) else {
            return;
        };
        tester
            .search_parent_dup()
            .expect_no_blobs_request()
            .expect_no_block_request();
    }

    // This test no longer applies, we don't issue requests for child lookups
    // Keep for after updating rules on fetching blocks only first
    #[ignore]
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
