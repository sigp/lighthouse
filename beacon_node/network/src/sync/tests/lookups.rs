use crate::NetworkMessage;
use crate::metrics::{
    SYNC_LOOKUP_COMPLETED, SYNC_LOOKUP_DROPPED, SYNCING_CHAINS_ADDED,
    SYNCING_CHAINS_PROCESSED_BATCHES,
};
use crate::network_beacon_processor::{InvalidBlockStorage, NetworkBeaconProcessor};
use crate::sync::block_lookups::{
    BlockLookupSummary, PARENT_DEPTH_TOLERANCE, SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
};
use crate::sync::{
    SyncMessage,
    manager::{BlockProcessType, BlockProcessingResult, SyncManager},
};
use std::sync::Arc;
use std::time::Duration;

use super::*;

use crate::sync::block_lookups::common::ResponseType;
use beacon_chain::observed_data_sidecars::Observe;
use beacon_chain::{
    AvailabilityPendingExecutedBlock, AvailabilityProcessingStatus, BlockError,
    PayloadVerificationOutcome, PayloadVerificationStatus,
    blob_verification::GossipVerifiedBlob,
    block_verification_types::{AsBlock, BlockImportData},
    data_availability_checker::Availability,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, NumBlobs,
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec,
    },
    validator_monitor::timestamp_now,
};
use beacon_processor::{BeaconProcessorChannels, DuplicateCache, Work, WorkEvent};
use lighthouse_network::discovery::CombinedKey;
use lighthouse_network::{
    NetworkConfig, NetworkGlobals, PeerId,
    rpc::{RPCError, RequestType, RpcErrorResponse},
    service::api_types::{
        AppRequestId, DataColumnsByRootRequestId, DataColumnsByRootRequester, Id,
        SingleLookupReqId, SyncRequestId,
    },
    types::SyncState,
};
use slot_clock::{SlotClock, TestingSlotClock};
use tokio::sync::mpsc;
use tracing::info;
use types::{
    BeaconState, BeaconStateBase, BlobSidecar, BlockImportSource, DataColumnSidecar, EthSpec,
    ForkContext, ForkName, Hash256, MinimalEthSpec as E, SignedBeaconBlock, Slot,
    data_column_sidecar::ColumnIndex,
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
};

const D: Duration = Duration::new(0, 0);
const PARENT_FAIL_TOLERANCE: u8 = SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;
type DCByRootIds = Vec<DCByRootId>;
type DCByRootId = (SyncRequestId, Vec<ColumnIndex>);

/// Instruct the testing rig how to complete requests for _by_range requests
#[derive(Default)]
pub struct CompleteStrategy {
    block_count: usize,
    with_data: bool,
    custody_failure_at_index: Option<u64>,
    return_rpc_error: Option<RPCError>,
    empty_sampling_response_once: bool,
    stop_at_block: Option<Hash256>,
    return_wrong_blocks_n_times: usize,
    return_wrong_data_n_times: usize,
    return_no_blocks_n_times: usize,
    return_no_data_n_times: usize,
    return_too_few_data_n_times: usize,
    skip_by_range_routes: bool,
    process_result: Option<BlockProcessingResult>,
}

impl CompleteStrategy {
    fn new() -> Self {
        Self::default()
    }

    fn happy_path() -> Self {
        Self::default()
    }

    fn return_no_blocks_always(mut self: Self) -> Self {
        self.return_no_blocks_n_times = usize::MAX;
        self
    }

    fn return_no_blocks_once(mut self: Self) -> Self {
        self.return_no_blocks_n_times = 1;
        self
    }

    fn return_no_data_once(mut self: Self) -> Self {
        self.return_no_data_n_times = 1;
        self
    }

    fn return_wrong_blocks_once(mut self: Self) -> Self {
        self.return_wrong_blocks_n_times = 1;
        self
    }

    fn return_wrong_data_once(mut self: Self) -> Self {
        self.return_wrong_data_n_times = 1;
        self
    }

    fn return_too_few_data_once(mut self) -> Self {
        self.return_too_few_data_n_times = 1;
        self
    }

    fn return_rpc_error(mut self: Self, error: RPCError) -> Self {
        self.return_rpc_error = Some(error);
        self
    }

    fn no_range_sync(mut self: Self) -> Self {
        self.skip_by_range_routes = true;
        self
    }

    fn process_result(mut self: Self, result: BlockProcessingResult) -> Self {
        self.process_result = Some(result);
        self
    }
}

impl TestRig {
    pub fn test_setup() -> Self {
        // Use `fork_from_env` logic to set correct fork epochs
        let spec = Arc::new(test_spec::<E>());

        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(spec.clone())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(0),
                Duration::from_secs(12),
            ))
            .build();

        // Initialise a new beacon chain
        let external_harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(spec)
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(0),
                Duration::from_secs(12),
            ))
            .build();

        let chain = harness.chain.clone();
        let fork_context = Arc::new(ForkContext::new::<E>(
            Slot::new(0),
            chain.genesis_validators_root,
            &chain.spec,
        ));

        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let (sync_tx, sync_rx) = mpsc::unbounded_channel::<SyncMessage<E>>();
        // TODO(das): make the generation of the ENR use the deterministic rng to have consistent
        // column assignments
        let network_config = Arc::new(NetworkConfig::default());
        let globals = Arc::new(NetworkGlobals::new_test_globals(
            Vec::new(),
            network_config,
            chain.spec.clone(),
        ));

        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx,
        } = <_>::default();

        let beacon_processor = NetworkBeaconProcessor {
            beacon_processor_send: beacon_processor_tx,
            duplicate_cache: DuplicateCache::default(),
            chain: chain.clone(),
            // TODO: What is this sender used for?
            network_tx: mpsc::unbounded_channel().0,
            sync_tx,
            network_globals: globals.clone(),
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor: harness.runtime.task_executor.clone(),
        };

        let fork_name = chain.spec.fork_name_at_slot::<E>(chain.slot().unwrap());

        // All current tests expect synced and EL online state
        beacon_processor
            .network_globals
            .set_sync_state(SyncState::Synced);

        let spec = chain.spec.clone();

        // deterministic seed
        let rng_08 = <rand_chacha_03::ChaCha20Rng as rand_08::SeedableRng>::from_seed([0u8; 32]);
        let rng = ChaCha20Rng::from_seed([0u8; 32]);

        init_tracing();

        let mut network_blocks_by_root = HashMap::new();
        let mut network_blocks_by_slot = HashMap::new();

        // Add genesis block for completeness
        let genesis_block = external_harness.get_head_block();
        network_blocks_by_root.insert(genesis_block.canonical_root(), genesis_block.clone());
        network_blocks_by_slot.insert(genesis_block.slot(), genesis_block);

        TestRig {
            beacon_processor_rx,
            beacon_processor_rx_queue: vec![],
            network_rx,
            network_rx_queue: vec![],
            sync_rx,
            rng_08,
            rng,
            network_globals: beacon_processor.network_globals.clone(),
            sync_manager: SyncManager::new(
                chain,
                network_tx,
                beacon_processor.into(),
                // Pass empty recv not tied to any tx
                mpsc::unbounded_channel().1,
                fork_context,
            ),
            harness,
            external_harness,
            fork_name,
            spec,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            network_blocks_by_root,
            network_blocks_by_slot,
            penalties: <_>::default(),
            seen_lookups: <_>::default(),
            requests: <_>::default(),
            complete_strategy: <_>::default(),
        }
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    // Network / external peers simulated behaviour

    fn simulate(&mut self, complete_strategy: CompleteStrategy) {
        self.complete_strategy = complete_strategy;

        let mut i = 0;

        loop {
            i += 1;

            // Record current status
            for (id, block_root, awaiting_parent, peers) in
                self.sync_manager.active_single_lookups()
            {
                let mut lookup = self.seen_lookups.entry(id).or_insert(SeenLookup {
                    block_root,
                    max_seen_peers: <_>::default(),
                });
                for peer in peers {
                    lookup.max_seen_peers.insert(peer);
                }
            }

            if let Ok(sync_message) = self.sync_rx.try_recv() {
                self.log(&format!(
                    "Tick {i}: sync_rx event: {}",
                    Into::<&'static str>::into(&sync_message)
                ));
                self.sync_manager.handle_message(sync_message);
                continue;
            }

            // TODO(tree-sync): Change the order in which responses are processed. Like:
            // - By insertion order
            // - First blocks
            // - Blocks last
            // - Max slot first
            // - Min slot first
            if let Ok(event) = self.network_rx.try_recv() {
                self.log(&format!("Tick {i}: network_rx event: {event:?}"));
                match event {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request,
                        app_request_id,
                    } => {
                        self.simulate_on_request(peer_id, request, app_request_id);
                    }
                    NetworkMessage::ReportPeer {
                        peer_id,
                        action,
                        source,
                        msg,
                    } => {
                        self.penalties.push(ReportedPenalty {
                            peer_id,
                            action,
                            source,
                            msg,
                        });
                    }
                    _ => {}
                }
                continue;
            }

            if let Ok(event) = self.beacon_processor_rx.try_recv() {
                self.log(&format!("Tick {i}: beacon_processor event: {event:?}"));
                match event.work {
                    Work::RpcBlock { process_fn } => self.runtime.block_on(process_fn),
                    Work::ChainSegment(process_fn) => self.runtime.block_on(process_fn),
                    Work::Reprocess(_) => {} // ignore
                    other => panic!("Unsupported Work event {}", other.str_id()),
                }
                continue;
            }

            break;
        }
    }

    fn simulate_on_request(
        &mut self,
        peer_id: PeerId,
        request: RequestType<E>,
        app_req_id: AppRequestId,
    ) {
        self.requests.push((request.clone(), app_req_id));

        if let AppRequestId::Sync(req_id) = app_req_id {
            if let Some(error) = self.complete_strategy.return_rpc_error.take() {
                self.log(&format!(
                    "Completing request {req_id:?} to {peer_id} with RPCError {error:?}"
                ));
                self.send_sync_message(SyncMessage::RpcError {
                    sync_request_id: req_id,
                    peer_id,
                    error,
                });
                return;
            }
        }

        match (request, app_req_id) {
            (RequestType::BlocksByRoot(req), AppRequestId::Sync(req_id)) => {
                let blocks =
                    req.block_roots()
                        .iter()
                        .filter_map(|block_root| {
                            if self.complete_strategy.return_no_blocks_n_times > 0 {
                                self.complete_strategy.return_no_blocks_n_times -= 1;
                                None
                            } else if self.complete_strategy.return_wrong_blocks_n_times > 0 {
                                self.complete_strategy.return_wrong_blocks_n_times -= 1;
                                Some(Arc::new(self.rand_block()))
                            } else {
                                Some(self.network_blocks_by_root
                                .get(block_root)
                                .unwrap_or_else(|| {
                                    panic!("Test consumer requested unknown block: {block_root:?}")
                                })
                                .block_cloned())
                            }
                        })
                        .collect::<Vec<_>>();

                self.send_rpc_blocks_response(req_id, peer_id, &blocks);
            }

            (RequestType::BlocksByRange(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.skip_by_range_routes {
                    return;
                }
                let blocks = (*req.start_slot()..req.start_slot() + req.count())
                    .filter_map(|slot| {
                        self.network_blocks_by_slot
                            .get(&Slot::new(slot))
                            .map(|block| block.block_cloned())
                    })
                    .collect::<Vec<_>>();

                self.send_rpc_blocks_response(req_id, peer_id, &blocks);
            }

            (RequestType::Status(_req), AppRequestId::Router) => {
                // Ignore Status requests for now
            }

            other => panic!("Request not supported: {app_req_id:?} {other:?}"),
        }
    }

    fn send_rpc_blocks_response(
        &mut self,
        sync_request_id: SyncRequestId,
        peer_id: PeerId,
        blocks: &[Arc<SignedBeaconBlock<E>>],
    ) {
        let slots = blocks.iter().map(|block| block.slot()).collect::<Vec<_>>();
        self.log(&format!(
            "Completing request {sync_request_id:?} to {peer_id} with blocks {slots:?}"
        ));

        for block in blocks {
            self.push_sync_message(SyncMessage::RpcBlock {
                sync_request_id,
                peer_id,
                beacon_block: Some(block.clone()),
                seen_timestamp: D,
            });
        }
        self.push_sync_message(SyncMessage::RpcBlock {
            sync_request_id,
            peer_id,
            beacon_block: None,
            seen_timestamp: D,
        });
    }

    // Preparation steps

    fn build_chain(&mut self, block_count: usize) {
        let mut blocks = vec![];

        for i in 0..block_count {
            self.external_harness.advance_slot();
            let block_root = self.runtime().block_on(self.external_harness.extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            ));
            let block = self.external_harness.get_full_block(&block_root);
            let block_root = block.canonical_root();
            let block_slot = block.slot();
            self.network_blocks_by_root
                .insert(block_root, block.clone());
            self.network_blocks_by_slot.insert(block_slot, block);
            self.log(&format!(
                "Producing block {} index {i} in external harness",
                block_slot,
            ));
            blocks.push((block_slot, block_root));
        }

        // Re-log to have a nice list of block roots at the end
        for block in blocks {
            self.log(&format!("Build chain {block:?}"));
        }

        // Auto-update the clock on the main harness to accept the blocks
        self.harness
            .set_current_slot(self.external_harness.get_current_slot());
    }

    fn get_last_block(&self) -> &RpcBlock<E> {
        let (_, last_block) = self
            .network_blocks_by_root
            .iter()
            .max_by_key(|(_, block)| block.slot())
            .expect("no blocks");
        last_block
    }

    /// Trigger a lookup with the last created block
    fn trigger_with_last_block(&mut self) {
        let peer_id = self.new_connected_peer();
        let last_block = self.get_last_block().canonical_root();
        self.trigger_unknown_block_from_attestation(last_block, peer_id);
    }

    fn block_at_slot(&self, slot: u64) -> Arc<SignedBeaconBlock<E>> {
        self.network_blocks_by_slot
            .get(&Slot::new(slot))
            .unwrap_or_else(|| panic!("No block for slot {slot}"))
            .block_cloned()
    }

    fn block_root_at_slot(&self, slot: u64) -> Hash256 {
        self.block_at_slot(slot).canonical_root()
    }

    fn trigger_with_block_at_slot(&mut self, slot: u64) {
        let peer_id = self.new_connected_peer();
        let block = self.block_at_slot(slot);
        self.trigger_unknown_block_from_attestation(block.canonical_root(), peer_id);
    }

    fn trigger_with_single_block(&mut self) {
        self.build_chain(1);
        self.trigger_with_last_block();
    }

    fn build_chain_and_trigger_last_block(&mut self, block_count: usize) {
        self.build_chain(block_count);
        self.trigger_with_last_block();
    }

    fn trigger_with_last_unknown_block_parent(&mut self) {
        let peer_id = self.new_connected_peer();
        let last_block = self.get_last_block().block_cloned();
        self.trigger_unknown_parent_block(peer_id, last_block);
    }

    fn trigger_with_last_unknown_blob_parent(&mut self) {
        let peer_id = self.new_connected_peer();
        let blob = self
            .get_last_block()
            .blobs()
            .expect("no blobs")
            .first()
            .expect("empty blobs");
        self.trigger_unknown_parent_blob(peer_id, blob.clone());
    }

    fn trigger_with_last_unknown_data_column_parent(&mut self) {
        let peer_id = self.new_connected_peer();
        let column = self
            .get_last_block()
            .custody_columns()
            .expect("No custody columns")
            .first()
            .expect("empty columns");
        self.trigger_unknown_parent_column(peer_id, column.as_data_column().clone());
    }

    // Post-test assertions

    fn assert_head_slot(&self, slot: u64) {
        assert_eq!(
            self.harness.chain.head().head_slot(),
            Slot::new(slot),
            "Unexpected head slot"
        );
    }

    fn expect_penalties(&self, expected_penalties: &[&'static str]) {
        let penalties = self
            .penalties
            .iter()
            .map(|penalty| penalty.msg)
            .collect::<Vec<_>>();
        assert_eq!(penalties, expected_penalties, "Unexpected penalties");
    }

    fn assert_failed_lookup_sync(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.completed_lookups(), 0, "some completed lookups");
        assert_eq!(
            self.dropped_lookups(),
            self.created_lookups(),
            "not all dropped"
        );
        self.expect_empty_network();
        self.expect_no_active_lookups();
    }

    fn assert_successful_lookup_sync(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(
            self.completed_lookups(),
            self.created_lookups(),
            "not all completed"
        );
        assert_eq!(self.dropped_lookups(), 0, "some dropped lookups");
        self.expect_empty_network();
        self.expect_no_active_lookups();
    }

    fn assert_successful_range_sync(&self) {
        todo!("Check that range sync run, completed, no failed chains");
    }

    /// Total count of unique lookups created
    fn created_lookups(&self) -> usize {
        self.sync_manager.block_lookups().metrics().created_lookups
    }

    /// Total count of lookups completed or dropped
    fn dropped_lookups(&self) -> usize {
        self.sync_manager.block_lookups().metrics().dropped_lookups
    }

    fn completed_lookups(&self) -> usize {
        self.sync_manager
            .block_lookups()
            .metrics()
            .completed_lookups
    }

    fn lookup_by_root(&self, block_root: Hash256) -> &SeenLookup {
        self.seen_lookups
            .values()
            .find(|lookup| lookup.block_root == block_root)
            .unwrap_or_else(|| panic!("No loookup for block_root {block_root}"))
    }

    // Test setup

    fn test_setup_after_deneb() -> Option<Self> {
        let r = Self::test_setup();
        if r.after_deneb() { Some(r) } else { None }
    }
    fn test_setup_after_deneb_before_fulu() -> Option<Self> {
        let r = Self::test_setup();
        if r.after_deneb() && !r.fork_name.fulu_enabled() {
            Some(r)
        } else {
            None
        }
    }

    pub fn test_setup_after_fulu() -> Option<Self> {
        let r = Self::test_setup();
        if r.fork_name.fulu_enabled() {
            Some(r)
        } else {
            None
        }
    }

    pub fn log(&self, msg: &str) {
        info!(msg, "TEST_RIG");
    }

    pub fn after_deneb(&self) -> bool {
        self.fork_name.deneb_enabled()
    }

    pub fn after_fulu(&self) -> bool {
        self.fork_name.fulu_enabled()
    }

    fn trigger_unknown_parent_block(&mut self, peer_id: PeerId, block: Arc<SignedBeaconBlock<E>>) {
        let block_root = block.canonical_root();
        self.send_sync_message(SyncMessage::UnknownParentBlock(peer_id, block, block_root))
    }

    fn trigger_unknown_parent_blob(&mut self, peer_id: PeerId, blob: Arc<BlobSidecar<E>>) {
        self.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, blob));
    }

    fn trigger_unknown_parent_column(
        &mut self,
        peer_id: PeerId,
        column: Arc<DataColumnSidecar<E>>,
    ) {
        self.send_sync_message(SyncMessage::UnknownParentDataColumn(peer_id, column));
    }

    fn trigger_unknown_block_from_attestation(&mut self, block_root: Hash256, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
            peer_id, block_root,
        ));
    }

    /// Drain all sync messages in the sync_rx attached to the beacon processor
    fn drain_sync_rx(&mut self) {
        while let Ok(sync_message) = self.sync_rx.try_recv() {
            self.send_sync_message(sync_message);
        }
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

    fn rand_block_and_data_columns(
        &mut self,
    ) -> (SignedBeaconBlock<E>, Vec<Arc<DataColumnSidecar<E>>>) {
        let num_blobs = NumBlobs::Number(1);
        generate_rand_block_and_data_columns::<E>(
            self.fork_name,
            num_blobs,
            &mut self.rng,
            &self.harness.spec,
        )
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

    pub fn send_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.handle_message(sync_message);
    }

    pub fn push_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.send_sync_message(sync_message);
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

    fn active_range_sync_chain(&self) -> (RangeSyncType, Slot, Slot) {
        self.sync_manager
            .get_range_sync_chains()
            .unwrap()
            .expect("No sync chains")
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

    fn insert_ignored_chain(&mut self, block_root: Hash256) {
        self.sync_manager.insert_ignored_chain(block_root);
    }

    fn assert_not_ignored_chain(&mut self, chain_hash: Hash256) {
        let chains = self.sync_manager.get_ignored_chains();
        if chains.contains(&chain_hash) {
            panic!("ignored chains contain {chain_hash:?}: {chains:?}");
        }
    }

    fn assert_ignored_chain(&mut self, chain_hash: Hash256) {
        let chains = self.sync_manager.get_ignored_chains();
        if !chains.contains(&chain_hash) {
            panic!("expected ignored chains to contain {chain_hash:?}: {chains:?}");
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

    pub fn new_connected_peer(&mut self) -> PeerId {
        let key = self.determinstic_key();
        let peer_id = self
            .network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(false, &self.harness.spec, key);
        self.log(&format!("Added new peer for testing {peer_id:?}"));
        peer_id
    }

    pub fn new_connected_supernode_peer(&mut self) -> PeerId {
        let key = self.determinstic_key();
        self.network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(true, &self.harness.spec, key)
    }

    fn determinstic_key(&mut self) -> CombinedKey {
        k256::ecdsa::SigningKey::random(&mut self.rng_08).into()
    }

    pub fn new_connected_peers_for_peerdas(&mut self) {
        // Enough sampling peers with few columns
        for _ in 0..100 {
            self.new_connected_peer();
        }
        // One supernode peer to ensure all columns have at least one peer
        self.new_connected_supernode_peer();
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

    fn parent_block_processed(&mut self, chain_hash: Hash256, result: BlockProcessingResult) {
        let id = self.find_single_lookup_for(self.find_oldest_parent_lookup(chain_hash));
        self.single_block_component_processed(id, result);
    }

    fn parent_blob_processed(&mut self, chain_hash: Hash256, result: BlockProcessingResult) {
        let id = self.find_single_lookup_for(self.find_oldest_parent_lookup(chain_hash));
        self.single_blob_component_processed(id, result);
    }

    fn parent_block_processed_imported(&mut self, chain_hash: Hash256) {
        self.parent_block_processed(
            chain_hash,
            BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(chain_hash)),
        );
    }

    fn single_block_component_processed(&mut self, id: Id, result: BlockProcessingResult) {
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

    fn single_blob_component_processed(&mut self, id: Id, result: BlockProcessingResult) {
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
            sync_request_id: SyncRequestId::SingleBlock { id },
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
            sync_request_id: SyncRequestId::SingleBlock { id },
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
            sync_request_id: SyncRequestId::SingleBlob { id },
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
            sync_request_id: SyncRequestId::SingleBlob { id },
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
            sync_request_id: SyncRequestId::SingleBlock { id },
            error,
        })
    }

    fn parent_lookup_failed_unavailable(&mut self, id: SingleLookupReqId, peer_id: PeerId) {
        self.parent_lookup_failed(
            id,
            peer_id,
            RPCError::ErrorResponse(
                RpcErrorResponse::ResourceUnavailable,
                "older than deneb".into(),
            ),
        );
    }

    fn single_lookup_failed(&mut self, id: SingleLookupReqId, peer_id: PeerId, error: RPCError) {
        self.send_sync_message(SyncMessage::RpcError {
            peer_id,
            sync_request_id: SyncRequestId::SingleBlock { id },
            error,
        })
    }

    fn complete_valid_block_request(
        &mut self,
        id: SingleLookupReqId,
        block: Arc<SignedBeaconBlock<E>>,
        missing_components: bool,
    ) {
        // Complete download
        let peer_id = PeerId::random();
        let slot = block.slot();
        let block_root = block.canonical_root();
        self.single_lookup_block_response(id, peer_id, Some(block));
        self.single_lookup_block_response(id, peer_id, None);
        // Expect processing and resolve with import
        self.expect_block_process(ResponseType::Block);
        self.single_block_component_processed(
            id.lookup_id,
            if missing_components {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    slot, block_root,
                ))
            } else {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(block_root))
            },
        )
    }

    fn complete_valid_custody_request(
        &mut self,
        ids: DCByRootIds,
        data_columns: Vec<Arc<DataColumnSidecar<E>>>,
        missing_components: bool,
    ) {
        let lookup_id = if let SyncRequestId::DataColumnsByRoot(DataColumnsByRootRequestId {
            requester: DataColumnsByRootRequester::Custody(id),
            ..
        }) = ids.first().unwrap().0
        {
            id.requester.0.lookup_id
        } else {
            panic!("not a custody requester")
        };

        let first_column = data_columns.first().cloned().unwrap();

        for id in ids {
            self.log(&format!("return valid data column for {id:?}"));
            let indices = &id.1;
            let columns_to_send = indices
                .iter()
                .map(|&i| data_columns[i as usize].clone())
                .collect::<Vec<_>>();
            self.complete_data_columns_by_root_request(id, &columns_to_send);
        }

        // Expect work event
        self.expect_rpc_custody_column_work_event();

        // Respond with valid result
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type: BlockProcessType::SingleCustodyColumn(lookup_id),
            result: if missing_components {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::MissingComponents(
                    first_column.slot(),
                    first_column.block_root(),
                ))
            } else {
                BlockProcessingResult::Ok(AvailabilityProcessingStatus::Imported(
                    first_column.block_root(),
                ))
            },
        });
    }

    fn complete_data_columns_by_root_request(
        &mut self,
        (sync_request_id, _): DCByRootId,
        data_columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let peer_id = PeerId::random();
        for data_column in data_columns {
            // Send chunks
            self.send_sync_message(SyncMessage::RpcDataColumn {
                sync_request_id,
                peer_id,
                data_column: Some(data_column.clone()),
                seen_timestamp: timestamp_now(),
            });
        }
        // Send stream termination
        self.send_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id,
            peer_id,
            data_column: None,
            seen_timestamp: timestamp_now(),
        });
    }

    /// Return RPCErrors for all active requests of peer
    fn rpc_error_all_active_requests(&mut self, disconnected_peer_id: PeerId) {
        self.drain_network_rx();
        while let Ok(sync_request_id) = self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                app_request_id: AppRequestId::Sync(id),
                ..
            } if *peer_id == disconnected_peer_id => Some(*id),
            _ => None,
        }) {
            self.send_sync_message(SyncMessage::RpcError {
                peer_id: disconnected_peer_id,
                sync_request_id,
                error: RPCError::Disconnected,
            });
        }
    }

    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::Disconnect(peer_id));
    }

    fn get_connected_peers(&self) -> Vec<PeerId> {
        self.network_globals
            .peers
            .read()
            .peers()
            .map(|(peer, _)| *peer)
            .collect::<Vec<_>>()
    }

    fn disconnect_all_peers(&mut self) {
        for peer in self.get_connected_peers() {
            self.log(&format!("Disconnecting peer {peer}"));
            self.send_sync_message(SyncMessage::Disconnect(peer));
        }
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

    pub fn pop_received_network_event<T, F: Fn(&NetworkMessage<E>) -> Option<T>>(
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

    pub fn pop_received_processor_event<T, F: Fn(&WorkEvent<E>) -> Option<T>>(
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

    pub fn expect_empty_processor(&mut self) {
        self.drain_processor_rx();
        if !self.beacon_processor_rx_queue.is_empty() {
            panic!(
                "Expected processor to be empty, but has events: {:?}",
                self.beacon_processor_rx_queue
            );
        }
    }

    fn find_block_lookup_request(
        &mut self,
        for_block: Hash256,
    ) -> Result<SingleLookupReqId, String> {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: RequestType::BlocksByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
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
                request: RequestType::BlobsByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
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
                request: RequestType::BlocksByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
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
                request: RequestType::BlobsByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
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

    /// Retrieves an unknown number of requests for data columns of `block_root`. Because peer ENRs
    /// are random, and peer selection is random, the total number of batched requests is unknown.
    fn expect_data_columns_by_root_requests(
        &mut self,
        block_root: Hash256,
        count: usize,
    ) -> DCByRootIds {
        let mut requests: DCByRootIds = vec![];
        loop {
            let req = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: RequestType::DataColumnsByRoot(request),
                        app_request_id:
                            AppRequestId::Sync(id @ SyncRequestId::DataColumnsByRoot { .. }),
                    } => {
                        let matching = request
                            .data_column_ids
                            .iter()
                            .find(|id| id.block_root == block_root)?;

                        let indices = matching.columns.iter().copied().collect();
                        Some((*id, indices))
                    }
                    _ => None,
                })
                .unwrap_or_else(|e| {
                    panic!("Expected more DataColumnsByRoot requests for {block_root:?}: {e}")
                });
            requests.push(req);

            // Should never infinite loop because sync does not send requests for 0 columns
            if requests.iter().map(|r| r.1.len()).sum::<usize>() >= count {
                return requests;
            }
        }
    }

    fn expect_only_data_columns_by_root_requests(
        &mut self,
        for_block: Hash256,
        count: usize,
    ) -> DCByRootIds {
        let ids = self.expect_data_columns_by_root_requests(for_block, count);
        self.expect_empty_network();
        ids
    }

    #[track_caller]
    fn expect_block_process(&mut self, response_type: ResponseType) {
        match response_type {
            ResponseType::Block => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcBlock).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected block work event: {e}")),
            ResponseType::Blob => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcBlobs).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected blobs work event: {e}")),
            ResponseType::CustodyColumn => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcCustodyColumn).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected column work event: {e}")),
        }
    }

    fn expect_rpc_custody_column_work_event(&mut self) {
        self.pop_received_processor_event(|ev| {
            if ev.work_type() == beacon_processor::WorkType::RpcCustodyColumn {
                Some(())
            } else {
                None
            }
        })
        .unwrap_or_else(|e| panic!("Expected RPC custody column work: {e}"))
    }

    #[allow(dead_code)]
    fn expect_no_work_event(&mut self) {
        self.drain_processor_rx();
        assert!(self.network_rx_queue.is_empty());
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

    fn expect_no_penalties(&mut self) {
        self.drain_network_rx();
        let downscore_events = self
            .network_rx_queue
            .iter()
            .filter_map(|ev| match ev {
                NetworkMessage::ReportPeer {
                    peer_id: p_id, msg, ..
                } => Some(msg),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !downscore_events.is_empty() {
            panic!("Some downscore events: {downscore_events:?}");
        }
    }

    #[track_caller]
    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                // Parent chain sends blocks one by one
                assert_eq!(work.work_type(), beacon_processor::WorkType::RpcBlock);
            }
            other => panic!(
                "Expected rpc_block from chain segment process, found {:?}",
                other
            ),
        }
    }

    #[track_caller]
    pub fn expect_empty_network(&mut self) {
        self.drain_network_rx();
        if !self.network_rx_queue.is_empty() {
            let n = self.network_rx_queue.len();
            panic!(
                "expected no network events but got {n} events, displaying first 2: {:#?}",
                self.network_rx_queue[..n.min(2)].iter().collect::<Vec<_>>()
            );
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
        self.log(&format!("Found expected penalty {penalty_msg}"));
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
            .put_executed_block(executed_block)
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
            .put_gossip_verified_blobs(
                blob.block_root(),
                std::iter::once(GossipVerifiedBlob::<_, Observe>::__assumed_valid(
                    blob.into(),
                )),
            )
            .unwrap()
        {
            Availability::Available(_) => panic!("blob removed from da_checker, available"),
            Availability::MissingComponents(block_root) => {
                self.log(&format!("inserted blob to da_checker {block_root:?}"))
            }
        };
    }

    fn insert_block_to_availability_cache(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.harness
            .chain
            .data_availability_checker
            .put_pre_execution_block(block.canonical_root(), block, BlockImportSource::Gossip)
            .unwrap();
    }

    fn simulate_block_gossip_processing_becomes_invalid(&mut self, block_root: Hash256) {
        self.harness
            .chain
            .data_availability_checker
            .remove_block_on_execution_error(&block_root);

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

        self.insert_block_to_da_checker(block);

        self.send_sync_message(SyncMessage::GossipBlockProcessResult {
            block_root,
            imported: false,
        });
    }
}

#[macro_export]
macro_rules! assert_counter {
    // ------ IntCounter case ------
    ($metric:ident, $expected:expr) => {{
        let counter = $metric.as_ref().expect(concat!(
            "Failed to initialize metric: ",
            stringify!($metric)
        ));

        let actual = counter.get();

        assert!(
            actual == $expected,
            "Counter {} expected {}, got {}",
            stringify!($metric),
            $expected,
            actual
        );
    }};

    // ------ CounterVec case ------
    ($metric:ident, $labels:expr, $expected:expr) => {{
        let counter_vec = $metric.as_ref().expect(concat!(
            "Failed to initialize metric: ",
            stringify!($metric)
        ));

        // $labels is expected to be &[..] or &[&str; N]
        let counter = counter_vec.with_label_values($labels);

        let actual = counter.get();

        assert!(
            actual == $expected,
            "CounterVec {}{:?} expected {}, got {}",
            stringify!($metric),
            $labels,
            $expected,
            actual
        );
    }};
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

macro_rules! run_lookups_tests_for_depths {
    ($($depth:literal),+ $(,)?) => {
        paste::paste! {
            $(
                #[test]
                fn [<happy_path_unknown_attestation_depth_ $depth>]() {
                    happy_path_unknown_attestation($depth);
                }

                #[test]
                fn [<happy_path_unknown_block_parent_depth_ $depth>]() {
                    happy_path_unknown_block_parent($depth);
                }

                #[test]
                fn [<happy_path_unknown_data_parent_depth_ $depth>]() {
                    happy_path_unknown_data_parent($depth);
                }

                #[test]
                fn [<happy_path_multiple_triggers_depth_ $depth>]() {
                    happy_path_multiple_triggers($depth);
                }

                #[test]
                fn [<bad_peer_empty_block_response_depth_ $depth>]() {
                    bad_peer_empty_block_response($depth);
                }

                #[test]
                fn [<bad_peer_empty_data_response_depth_ $depth>]() {
                    bad_peer_empty_data_response($depth);
                }

                #[test]
                fn [<bad_peer_too_few_data_response_depth_ $depth>]() {
                    bad_peer_too_few_data_response($depth);
                }

                #[test]
                fn [<bad_peer_wrong_block_response_depth_ $depth>]() {
                    bad_peer_wrong_block_response($depth);
                }

                #[test]
                fn [<bad_peer_wrong_data_response_depth_ $depth>]() {
                    bad_peer_wrong_data_response($depth);
                }

                #[test]
                fn [<bad_peer_rpc_failure_depth_ $depth>]() {
                    bad_peer_rpc_failure($depth);
                }

                #[test]
                fn [<too_many_download_failures_depth_ $depth>]() {
                    too_many_download_failures($depth);
                }

                #[test]
                fn [<too_many_processing_failures_depth_ $depth>]() {
                    too_many_processing_failures($depth);
                }

                #[test]
                fn [<peer_disconnected_then_rpc_error_depth_ $depth>]() {
                    peer_disconnected_then_rpc_error($depth);
                }
            )+
        }
    };
}

run_lookups_tests_for_depths!(1, 2);

/// Assert that lookup sync succeeds with the happy case
fn happy_path_unknown_attestation(depth: usize) {
    let mut r = TestRig::test_setup();
    // We get attestation for a block descendant (depth) blocks of current head
    r.build_chain_and_trigger_last_block(depth);
    // Complete the request with good peer behaviour
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

fn happy_path_unknown_block_parent(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain(depth);
    r.trigger_with_last_unknown_block_parent();
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

/// Assert that sync completes from a GossipUnknownParentBlob / UknownDataColumnParent
fn happy_path_unknown_data_parent(depth: usize) {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    r.build_chain(depth);
    if r.after_deneb() {
        r.trigger_with_last_unknown_data_column_parent();
    } else {
        r.trigger_with_last_unknown_blob_parent();
    }
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

/// Assert that multiple trigger types don't create extra lookups
fn happy_path_multiple_triggers(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain(depth);
    r.trigger_with_last_block();
    r.trigger_with_last_unknown_block_parent();
    r.trigger_with_last_unknown_blob_parent();
    r.trigger_with_last_unknown_data_column_parent();
    r.assert_single_lookups_count(depth);
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

// Test bad behaviour of peers

/// Assert that if peer responds with no blocks, we downscore, and retry the same lookup
fn bad_peer_empty_block_response(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    // Simulate that peer returns empty response once, then good behaviour
    r.simulate(CompleteStrategy::new().return_no_blocks_once());
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();

    // TODO(tree-sync) For post-deneb assert that the blobs are not re-fetched
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with no blobs / columns, we downscore, and retry the same lookup
fn bad_peer_empty_data_response(depth: usize) {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth);
    r.simulate(CompleteStrategy::new().return_no_data_once());
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with not enough blobs / columns, we downscore, and retry the same
/// lookup
fn bad_peer_too_few_data_response(depth: usize) {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth);
    r.simulate(CompleteStrategy::new().return_too_few_data_once());
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blocks, we downscore, and retry the same lookup
fn bad_peer_wrong_block_response(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    r.simulate(CompleteStrategy::new().return_wrong_blocks_once());
    r.expect_penalties(&["UnrequestedBlockRoot"]);
    r.assert_successful_lookup_sync();

    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blobs / columns, we downscore, and retry the same lookup
fn bad_peer_wrong_data_response(depth: usize) {
    let Some(mut r) = TestRig::test_setup_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth);
    r.simulate(CompleteStrategy::new().return_wrong_data_once());
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that on network error, we DON'T downscore, and retry the same lookup
fn bad_peer_rpc_failure(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    r.simulate(CompleteStrategy::new().return_rpc_error(RPCError::UnsupportedProtocol));
    r.expect_no_penalties();
    r.assert_successful_lookup_sync();
}

// Test retry logic

/// Assert that on too many download failures the lookup fails, but we can still sync
fn too_many_download_failures(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    // Simulate that a peer always returns empty
    r.simulate(CompleteStrategy::new().return_no_blocks_always());
    // We register multiple penalties, the lookup fails and sync does not progress
    r.expect_penalties(&["NotEnoughResponsesReturned"; 4]);
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

/// Assert that on too many processing failures the lookup fails, but we can still sync
fn too_many_processing_failures(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    // Simulate that a peer always returns empty
    r.simulate(
        CompleteStrategy::new().process_result(BlockProcessingResult::Err(
            BlockError::BlockSlotLimitReached,
        )),
    );
    // We register multiple penalties, the lookup fails and sync does not progress
    r.expect_penalties(&["NotEnoughResponsesReturned"; 4]);
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
}

#[test]
/// Assert that if the beacon processor returns Ignored ???
fn test_single_block_lookup_ignored_response() {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(1);
    // Send an Ignored response, the request should be dropped
    r.simulate(CompleteStrategy::new().process_result(BlockProcessingResult::Ignored));
    // The block was not actually imported
    r.assert_head_slot(0);
    r.assert_successful_lookup_sync();
}

/// Assert that when peers disconnect the lookups are not dropped (kept with zero peers)
fn peer_disconnected_then_rpc_error(depth: usize) {
    let mut r = TestRig::test_setup();
    r.build_chain_and_trigger_last_block(depth);
    r.assert_single_lookups_count(depth);
    // The peer disconnect event reaches sync before the rpc error.
    r.disconnect_all_peers();
    // The lookup is not removed as it can still potentially make progress.
    r.assert_single_lookups_count(depth);
    r.simulate(CompleteStrategy::new().return_rpc_error(RPCError::Disconnected));

    assert!(r.created_lookups() > 0, "no created lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
    assert_eq!(r.dropped_lookups(), 0, "some dropped lookups");
    r.expect_empty_network();
    r.assert_single_lookups_count(depth);
}

#[test]
/// Assert that when creating multiple lookups their parent-child relation is discovered and we add
/// peers recursively from child to parent.
fn lookups_form_chain() {
    let depth = 5;
    let mut r = TestRig::test_setup();
    r.build_chain(depth);
    for slot in (1..=depth).rev() {
        r.trigger_with_block_at_slot(slot as u64);
    }
    // TODO(tree-sync): Assert that there are `depth` disjoint chains
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();

    // Assert that the peers are added to ancestor lookups,
    // - The lookup with max slot has 1 peer
    // - The lookup with min slot has all the peers
    for slot in 1..=(depth as u64) {
        let lookup = r.lookup_by_root(r.block_root_at_slot(slot));
        assert_eq!(
            lookup.max_seen_peers.len(),
            1 + depth - slot as usize,
            "Unexpected peer count for lookup at slot {slot}"
        );
    }
}

#[test]
/// Assert that if a lookup chain (by appending ancestors) is too long we drop it
fn test_parent_lookup_too_deep_grow_ancestor_one() {
    let mut r = TestRig::test_setup();
    r.build_chain(PARENT_DEPTH_TOLERANCE + 1);
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path());

    r.assert_head_slot(PARENT_DEPTH_TOLERANCE as u64 + 1);
    r.expect_no_penalties();
    // Should not penalize peer, but network is not clear because of the blocks_by_range requests
    // r.assert_ignored_chain(chain_hash);
    //
    // Assert that chain is in failed chains
    // Assert that there were 0 lookups completed, 33 dropped
    // Assert that there were 1 range sync chains
    // Bound resources:
    // - Limit amount of requests
    // - Limit the types of sync used
    assert_counter!(SYNC_LOOKUP_COMPLETED, 0);
    assert_counter!(
        SYNC_LOOKUP_DROPPED,
        &["chain_too_long"],
        PARENT_DEPTH_TOLERANCE as u64
    );
    assert_counter!(SYNCING_CHAINS_ADDED, &["Head"], 1);
    assert_counter!(SYNCING_CHAINS_PROCESSED_BATCHES, &["Head"], 5);
}

#[test]
fn test_parent_lookup_too_deep_grow_ancestor_zero() {
    let mut r = TestRig::test_setup();
    r.build_chain(PARENT_DEPTH_TOLERANCE);
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path());

    r.assert_head_slot(PARENT_DEPTH_TOLERANCE as u64);
    r.expect_no_penalties();
    assert_counter!(SYNC_LOOKUP_COMPLETED, PARENT_DEPTH_TOLERANCE as u64);
    assert_counter!(SYNC_LOOKUP_DROPPED, &["chain_too_long"], 0);
}

// Regression test for https://github.com/sigp/lighthouse/pull/7118
// 8042 UPDATE: block was previously added to the failed_chains cache, now it's inserted into the
// ignored chains cache. The regression test still applies as the chaild lookup is not created
#[test]
fn test_child_lookup_not_created_for_ignored_chain_parent_after_processing() {
    let mut r = TestRig::test_setup();
    r.build_chain(PARENT_DEPTH_TOLERANCE + 2);
    r.trigger_with_block_at_slot(PARENT_DEPTH_TOLERANCE as u64 + 1);
    r.simulate(CompleteStrategy::new().no_range_sync());

    // At this point, the chain should have been deemed too deep and pruned.
    // The tip root should have been inserted into ignored chains.
    // Ensure no blocks have been synced
    r.assert_head_slot(0);
    r.expect_no_active_lookups();
    r.expect_no_penalties();

    // WHEN: Trigger the extending block that points to the tip.
    r.trigger_with_block_at_slot(PARENT_DEPTH_TOLERANCE as u64 + 2);
    // THEN: The extending block should not create a lookup because the tip was inserted into
    // ignored chains.
    r.expect_no_active_lookups();
    r.expect_no_penalties();
    r.expect_empty_network();
}

#[test]
/// Assert that if a lookup chain (by appending tips) is too long we drop it
fn test_parent_lookup_too_deep_grow_tip() {
    let depth = PARENT_DEPTH_TOLERANCE + 1;
    let mut r = TestRig::test_setup();
    r.build_chain(depth);
    for slot in (1..=depth).rev() {
        r.trigger_with_block_at_slot(slot as u64);
    }
    r.simulate(CompleteStrategy::happy_path());

    assert!(r.created_lookups() > 0, "no created lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
    assert!(r.dropped_lookups() > 0, "no dropped lookups");
    r.assert_successful_range_sync();
    // Should not penalize peer, but network is not clear because of the blocks_by_range requests
    r.expect_no_penalties();
    r.assert_ignored_chain(r.block_at_slot(depth as u64).canonical_root());
}

#[test]
fn test_skip_creating_ignored_parent_lookup() {
    let mut rig = TestRig::test_setup();
    let (_, block, parent_root, _) = rig.rand_block_and_parent();
    let peer_id = rig.new_connected_peer();
    rig.insert_ignored_chain(parent_root);
    rig.trigger_unknown_parent_block(peer_id, block.into());
    rig.expect_no_penalty_for(peer_id);
    // Both current and parent lookup should not be created
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
                BlockError::DuplicateFullyImported(block.canonical_root()).into(),
            )
        } else {
            rig.log(&format!("Block {i} ParentUnknown"));
            rig.parent_block_processed(
                chain_hash,
                BlockProcessingResult::Err(BlockError::ParentUnknown {
                    parent_root: block.parent_root(),
                }),
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
/// Assert that if the lookup's block is in the da_checker we don't download it again
fn block_in_da_checker_skips_download() {
    // Only in Deneb, as the block needs blobs to remain in the da_checker
    let Some(mut r) = TestRig::test_setup_after_deneb_before_fulu() else {
        return;
    };
    // Add block to da_checker
    // Complete test with happy path
    // Assert that there were no requests for blocks
    r.build_chain(1);
    r.insert_block_to_da_checker(r.block_at_slot(1));
    r.trigger_with_block_at_slot(1);
    r.simulate(CompleteStrategy::happy_path());
    r.assert_successful_lookup_sync();
    assert_eq!(
        r.requests
            .iter()
            .filter(|(request, _)| matches!(request, RequestType::BlocksByRoot(_)))
            .collect::<Vec<_>>(),
        Vec::<&(RequestType<E>, AppRequestId)>::new(),
        "There should be no block requests"
    );
}

#[test]
fn block_in_processing_cache_becomes_invalid() {
    let Some(mut r) = TestRig::test_setup_after_deneb_before_fulu() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.insert_block_to_availability_cache(block.clone().into());
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
    let Some(mut r) = TestRig::test_setup_after_deneb_before_fulu() else {
        return;
    };
    let (block, blobs) = r.rand_block_and_blobs(NumBlobs::Number(1));
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.insert_block_to_availability_cache(block.clone().into());
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
    let Some(mut r) = TestRig::test_setup_after_deneb_before_fulu() else {
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

#[test]
fn custody_lookup_happy_path() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    let spec = E::default_spec();
    r.new_connected_peers_for_peerdas();
    let (block, data_columns) = r.rand_block_and_data_columns();
    let block_root = block.canonical_root();
    let peer_id = r.new_connected_peer();
    r.trigger_unknown_block_from_attestation(block_root, peer_id);
    // Should not request blobs
    let id = r.expect_block_lookup_request(block.canonical_root());
    r.complete_valid_block_request(id, block.into(), true);
    // for each slot we download `samples_per_slot` columns
    let sample_column_count = spec.samples_per_slot * spec.data_columns_per_group::<E>();
    let custody_ids =
        r.expect_only_data_columns_by_root_requests(block_root, sample_column_count as usize);
    r.complete_valid_custody_request(custody_ids, data_columns, false);
    r.expect_no_active_lookups();
}

// TODO(das): Test retries of DataColumnByRoot:
// - Expect request for column_index
// - Respond with bad data
// - Respond with stream terminator
//   ^ The stream terminator should be ignored and not close the next retry
