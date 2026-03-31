use super::*;
use crate::NetworkMessage;
use crate::network_beacon_processor::{
    ChainSegmentProcessId, InvalidBlockStorage, NetworkBeaconProcessor,
};
use crate::sync::block_lookups::{BlockLookupSummary, PARENT_DEPTH_TOLERANCE};
use crate::sync::{
    SyncMessage,
    manager::{BatchProcessResult, BlockProcessType, BlockProcessingResult, SyncManager},
};
use beacon_chain::blob_verification::KzgVerifiedBlob;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, EngineState, NotifyExecutionLayer,
    block_verification_types::{AsBlock, AvailableBlockData},
    data_availability_checker::Availability,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, NumBlobs,
        generate_rand_block_and_blobs, test_spec,
    },
};
use beacon_processor::{BeaconProcessorChannels, DuplicateCache, Work, WorkEvent};
use educe::Educe;
use itertools::Itertools;
use lighthouse_network::discovery::CombinedKey;
use lighthouse_network::{
    NetworkConfig, NetworkGlobals, PeerAction, PeerId,
    rpc::{RPCError, RequestType},
    service::api_types::{AppRequestId, SyncRequestId},
    types::SyncState,
};
use slot_clock::{SlotClock, TestingSlotClock};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;
use types::{
    BlobSidecar, BlockImportSource, ColumnIndex, DataColumnSidecar, EthSpec, ForkContext, ForkName,
    Hash256, MinimalEthSpec as E, SignedBeaconBlock, Slot,
    test_utils::{SeedableRng, XorShiftRng},
};

const D: Duration = Duration::new(0, 0);

/// Configuration for how the test rig should respond to sync requests.
///
/// Controls simulated peer behavior during lookup tests, including RPC errors,
/// invalid responses, and custom block processing results. Use builder methods
/// to configure specific failure scenarios.
#[derive(Default, Educe)]
#[educe(Debug)]
pub struct SimulateConfig {
    return_rpc_error: Option<RPCError>,
    return_wrong_blocks_n_times: usize,
    return_wrong_sidecar_for_block_n_times: usize,
    return_no_blocks_n_times: usize,
    return_no_data_n_times: usize,
    return_too_few_data_n_times: usize,
    return_no_columns_on_indices_n_times: usize,
    return_no_columns_on_indices: Vec<ColumnIndex>,
    skip_by_range_routes: bool,
    // Use a callable fn because BlockProcessingResult does not implement Clone
    #[educe(Debug(ignore))]
    process_result_conditional:
        Option<Box<dyn Fn(Hash256) -> Option<BlockProcessingResult> + Send + Sync>>,
    // Import a block directly before processing it (for simulating race conditions)
    import_block_before_process: HashSet<Hash256>,
    /// Number of range batch processing attempts that return FaultyFailure
    range_faulty_failures: usize,
    /// Number of range batch processing attempts that return NonFaultyFailure
    range_non_faulty_failures: usize,
    /// Number of BlocksByRange requests that return empty (no blocks)
    return_no_range_blocks_n_times: usize,
    /// Number of DataColumnsByRange requests that return empty (no columns)
    return_no_range_columns_n_times: usize,
    /// Number of DataColumnsByRange requests that return columns with unrequested indices
    return_wrong_range_column_indices_n_times: usize,
    /// Number of DataColumnsByRange requests that return columns with unrequested slots
    return_wrong_range_column_slots_n_times: usize,
    /// Number of DataColumnsByRange requests that return fewer columns than requested
    /// (drops half the columns). Triggers CouplingError::DataColumnPeerFailure → retry_partial_batch
    return_partial_range_columns_n_times: usize,
    /// Set EE offline at start, bring back online after this many BlocksByRange responses
    ee_offline_for_n_range_responses: Option<usize>,
    /// Disconnect all peers after this many successful BlocksByRange responses.
    successful_range_responses_before_disconnect: Option<usize>,
}

impl SimulateConfig {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn happy_path() -> Self {
        Self::default()
    }

    fn return_no_blocks_always(mut self) -> Self {
        self.return_no_blocks_n_times = usize::MAX;
        self
    }

    fn return_no_blocks_once(mut self) -> Self {
        self.return_no_blocks_n_times = 1;
        self
    }

    fn return_no_data_once(mut self) -> Self {
        self.return_no_data_n_times = 1;
        self
    }

    fn return_wrong_blocks_once(mut self) -> Self {
        self.return_wrong_blocks_n_times = 1;
        self
    }

    fn return_wrong_sidecar_for_block_once(mut self) -> Self {
        self.return_wrong_sidecar_for_block_n_times = 1;
        self
    }

    fn return_too_few_data_once(mut self) -> Self {
        self.return_too_few_data_n_times = 1;
        self
    }

    fn return_no_columns_on_indices(mut self, indices: &[ColumnIndex], times: usize) -> Self {
        self.return_no_columns_on_indices_n_times = times;
        self.return_no_columns_on_indices = indices.to_vec();
        self
    }

    pub(super) fn return_rpc_error(mut self, error: RPCError) -> Self {
        self.return_rpc_error = Some(error);
        self
    }

    fn no_range_sync(mut self) -> Self {
        self.skip_by_range_routes = true;
        self
    }

    fn with_process_result<F>(mut self, f: F) -> Self
    where
        F: Fn() -> BlockProcessingResult + Send + Sync + 'static,
    {
        self.process_result_conditional = Some(Box::new(move |_| Some(f())));
        self
    }

    fn with_import_block_before_process(mut self, block_root: Hash256) -> Self {
        self.import_block_before_process.insert(block_root);
        self
    }

    pub(super) fn with_range_faulty_failures(mut self, n: usize) -> Self {
        self.range_faulty_failures = n;
        self
    }

    pub(super) fn with_range_non_faulty_failures(mut self, n: usize) -> Self {
        self.range_non_faulty_failures = n;
        self
    }

    pub(super) fn with_no_range_blocks_n_times(mut self, n: usize) -> Self {
        self.return_no_range_blocks_n_times = n;
        self
    }

    pub(super) fn with_no_range_columns_n_times(mut self, n: usize) -> Self {
        self.return_no_range_columns_n_times = n;
        self
    }

    pub(super) fn with_wrong_range_column_indices_n_times(mut self, n: usize) -> Self {
        self.return_wrong_range_column_indices_n_times = n;
        self
    }

    pub(super) fn with_wrong_range_column_slots_n_times(mut self, n: usize) -> Self {
        self.return_wrong_range_column_slots_n_times = n;
        self
    }

    pub(super) fn with_partial_range_columns_n_times(mut self, n: usize) -> Self {
        self.return_partial_range_columns_n_times = n;
        self
    }

    pub(super) fn with_ee_offline_for_n_range_responses(mut self, n: usize) -> Self {
        self.ee_offline_for_n_range_responses = Some(n);
        self
    }

    pub(super) fn with_disconnect_after_range_requests(mut self, n: usize) -> Self {
        self.successful_range_responses_before_disconnect = Some(n);
        self
    }
}

fn genesis_fork() -> ForkName {
    test_spec::<E>().fork_name_at_slot::<E>(Slot::new(0))
}

pub(crate) struct TestRigConfig {
    fulu_test_type: FuluTestType,
    /// Override the node custody type derived from `fulu_test_type`
    node_custody_type_override: Option<NodeCustodyType>,
}

impl TestRig {
    pub(crate) fn new(test_rig_config: TestRigConfig) -> Self {
        // Use `fork_from_env` logic to set correct fork epochs
        let spec = Arc::new(test_spec::<E>());
        let clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            Duration::from_secs(12),
        );

        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(spec.clone())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(clock.clone())
            .node_custody_type(
                test_rig_config
                    .node_custody_type_override
                    .unwrap_or_else(|| test_rig_config.fulu_test_type.we_node_custody_type()),
            )
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

        // deterministic seed
        let rng_08 = <rand_chacha_03::ChaCha20Rng as rand_08::SeedableRng>::from_seed([0u8; 32]);
        let rng = ChaCha20Rng::from_seed([0u8; 32]);

        init_tracing();

        TestRig {
            beacon_processor_rx,
            beacon_processor_rx_queue: vec![],
            network_rx,
            network_rx_queue: vec![],
            sync_rx,
            sync_rx_queue: vec![],
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
            fork_name,
            network_blocks_by_root: <_>::default(),
            network_blocks_by_slot: <_>::default(),
            penalties: <_>::default(),
            seen_lookups: <_>::default(),
            requests: <_>::default(),
            complete_strategy: <_>::default(),
            initial_block_lookups_metrics: <_>::default(),
            fulu_test_type: test_rig_config.fulu_test_type,
        }
    }

    pub fn default() -> Self {
        // Before Fulu, FuluTestType is irrelevant
        Self::new(TestRigConfig {
            fulu_test_type: FuluTestType::WeFullnodeThemSupernode,
            node_custody_type_override: None,
        })
    }

    #[allow(dead_code)]
    pub fn with_custody_type(node_custody_type: NodeCustodyType) -> Self {
        Self::new(TestRigConfig {
            fulu_test_type: FuluTestType::WeFullnodeThemSupernode,
            node_custody_type_override: Some(node_custody_type),
        })
    }

    /// Runs the sync simulation until all event queues are empty.
    ///
    /// Processes events from sync_rx (sink), beacon processor, and network queues in fixed
    /// priority order each tick. Handles completed work before pulling new requests.
    pub(super) async fn simulate(&mut self, complete_strategy: SimulateConfig) {
        self.complete_strategy = complete_strategy;
        self.log(&format!(
            "Running simulate with config {:?}",
            self.complete_strategy
        ));

        // Set EE offline at the start if configured
        if self
            .complete_strategy
            .ee_offline_for_n_range_responses
            .is_some()
        {
            self.sync_manager
                .update_execution_engine_state(EngineState::Offline);
        }

        let mut i = 0;

        loop {
            i += 1;

            // Record current status
            for BlockLookupSummary {
                id,
                block_root,
                peers,
                ..
            } in self.active_single_lookups()
            {
                let lookup = self.seen_lookups.entry(id).or_insert(SeenLookup {
                    id,
                    block_root,
                    seen_peers: <_>::default(),
                });
                for peer in peers {
                    lookup.seen_peers.insert(peer);
                }
            }

            // Drain all channels into queues
            while let Ok(ev) = self.network_rx.try_recv() {
                self.network_rx_queue.push(ev);
            }
            while let Ok(ev) = self.beacon_processor_rx.try_recv() {
                self.beacon_processor_rx_queue.push(ev);
            }
            while let Ok(ev) = self.sync_rx.try_recv() {
                self.sync_rx_queue.push(ev);
            }

            // Process one event per tick in fixed priority: sink → processor → network
            if !self.sync_rx_queue.is_empty() {
                let sync_message = self.sync_rx_queue.remove(0);
                self.log(&format!(
                    "Tick {i}: sync_rx event: {}",
                    Into::<&'static str>::into(&sync_message)
                ));
                self.sync_manager.handle_message(sync_message);
            } else if !self.beacon_processor_rx_queue.is_empty() {
                let event = self.beacon_processor_rx_queue.remove(0);
                self.log(&format!("Tick {i}: beacon_processor event: {event:?}"));
                match event.work {
                    Work::RpcBlock {
                        process_fn,
                        beacon_block_root,
                    } => {
                        // Import block before processing if configured (for simulating race conditions)
                        if self
                            .complete_strategy
                            .import_block_before_process
                            .contains(&beacon_block_root)
                        {
                            self.log(&format!(
                                "Importing block {} before processing (race condition simulation)",
                                beacon_block_root
                            ));
                            self.import_block_by_root(beacon_block_root).await;
                        }

                        if let Some(f) = self.complete_strategy.process_result_conditional.as_ref()
                            && let Some(result) = f(beacon_block_root)
                        {
                            let id = self.lookup_by_root(beacon_block_root).id;
                            self.log(&format!(
                                "Sending custom process result to lookup id {id}: {result:?}"
                            ));
                            self.push_sync_message(SyncMessage::BlockComponentProcessed {
                                process_type: BlockProcessType::SingleBlock { id },
                                result,
                            });
                        } else {
                            process_fn.await
                        }
                    }
                    Work::RpcBlobs { process_fn } | Work::RpcCustodyColumn(process_fn) => {
                        process_fn.await
                    }
                    Work::ChainSegment {
                        process_fn,
                        process_id: (chain_id, batch_epoch),
                    } => {
                        let sync_type =
                            ChainSegmentProcessId::RangeBatchId(chain_id, batch_epoch.into());
                        if self.complete_strategy.range_faulty_failures > 0 {
                            self.complete_strategy.range_faulty_failures -= 1;
                            self.push_sync_message(SyncMessage::BatchProcessed {
                                sync_type,
                                result: BatchProcessResult::FaultyFailure {
                                    imported_blocks: 0,
                                    penalty: PeerAction::LowToleranceError,
                                },
                            });
                        } else if self.complete_strategy.range_non_faulty_failures > 0 {
                            self.complete_strategy.range_non_faulty_failures -= 1;
                            self.push_sync_message(SyncMessage::BatchProcessed {
                                sync_type,
                                result: BatchProcessResult::NonFaultyFailure,
                            });
                        } else {
                            process_fn.await;
                        }
                    }
                    Work::Reprocess(_) => {} // ignore
                    other => panic!("Unsupported Work event {}", other.str_id()),
                }
            } else if !self.network_rx_queue.is_empty() {
                let event = self.network_rx_queue.remove(0);
                self.log(&format!("Tick {i}: network_rx event: {event:?}"));
                match event {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request,
                        app_request_id,
                    } => {
                        self.simulate_on_request(peer_id, request, app_request_id);
                    }
                    NetworkMessage::ReportPeer { peer_id, msg, .. } => {
                        self.penalties.push(ReportedPenalty { peer_id, msg });
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }

        self.log("No more events in simulation");
        self.log(&format!(
            "Lookup metrics: {:?}",
            self.sync_manager.block_lookups().metrics()
        ));
        self.log(&format!(
            "Range sync metrics: {:?}",
            self.sync_manager.range_sync().metrics()
        ));
        self.log(&format!(
            "Max known slot: {}, Head slot: {}",
            self.max_known_slot(),
            self.head_slot()
        ));
        self.log(&format!("Penalties: {:?}", self.penalties));
        self.log(&format!(
            "Total requests {}: {:?}",
            self.requests.len(),
            self.requests_count()
        ))
    }

    fn simulate_on_request(
        &mut self,
        peer_id: PeerId,
        request: RequestType<E>,
        app_req_id: AppRequestId,
    ) {
        self.requests.push((request.clone(), app_req_id));

        if let AppRequestId::Sync(req_id) = app_req_id
            && let Some(error) = self.complete_strategy.return_rpc_error.take()
        {
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

            (RequestType::BlobsByRoot(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.return_no_data_n_times > 0 {
                    self.complete_strategy.return_no_data_n_times -= 1;
                    return self.send_rpc_blobs_response(req_id, peer_id, &[]);
                }

                let mut blobs = req
                    .blob_ids
                    .iter()
                    .map(|id| {
                        self.network_blocks_by_root
                            .get(&id.block_root)
                            .unwrap_or_else(|| {
                                panic!("Test consumer requested unknown block: {id:?}")
                            })
                            .block_data()
                            .blobs()
                            .unwrap_or_else(|| panic!("Block {id:?} has no blobs"))
                            .iter()
                            .find(|blob| blob.index == id.index)
                            .unwrap_or_else(|| panic!("Blob id {id:?} not avail"))
                            .clone()
                    })
                    .collect::<Vec<_>>();

                if self.complete_strategy.return_too_few_data_n_times > 0 {
                    self.complete_strategy.return_too_few_data_n_times -= 1;
                    blobs.pop();
                }

                if self
                    .complete_strategy
                    .return_wrong_sidecar_for_block_n_times
                    > 0
                {
                    self.complete_strategy
                        .return_wrong_sidecar_for_block_n_times -= 1;
                    let first = blobs.first_mut().expect("empty blobs");
                    let mut blob = Arc::make_mut(first).clone();
                    blob.signed_block_header.message.body_root = Hash256::ZERO;
                    *first = Arc::new(blob);
                }

                self.send_rpc_blobs_response(req_id, peer_id, &blobs);
            }

            (RequestType::DataColumnsByRoot(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.return_no_data_n_times > 0 {
                    self.complete_strategy.return_no_data_n_times -= 1;
                    return self.send_rpc_columns_response(req_id, peer_id, &[]);
                }

                let will_omit_columns = req.data_column_ids.iter().any(|id| {
                    id.columns.iter().any(|c| {
                        self.complete_strategy
                            .return_no_columns_on_indices
                            .contains(c)
                    })
                });
                let columns_to_omit = if will_omit_columns
                    && self.complete_strategy.return_no_columns_on_indices_n_times > 0
                {
                    self.log(&format!("OMIT {:?}", req));
                    self.complete_strategy.return_no_columns_on_indices_n_times -= 1;
                    self.complete_strategy.return_no_columns_on_indices.clone()
                } else {
                    vec![]
                };

                let mut columns = req
                    .data_column_ids
                    .iter()
                    .flat_map(|id| {
                        let block_columns = self
                            .network_blocks_by_root
                            .get(&id.block_root)
                            .unwrap_or_else(|| {
                                panic!("Test consumer requested unknown block: {id:?}")
                            })
                            .block_data()
                            .data_columns()
                            .unwrap_or_else(|| panic!("Block id {id:?} has no columns"));
                        id.columns
                            .iter()
                            .filter(|index| !columns_to_omit.contains(index))
                            .map(move |index| {
                                block_columns
                                    .iter()
                                    .find(|c| *c.index() == *index)
                                    .unwrap_or_else(|| {
                                        panic!("Column {index:?} {:?} not found", id.block_root)
                                    })
                                    .clone()
                            })
                    })
                    .collect::<Vec<_>>();

                if self.complete_strategy.return_too_few_data_n_times > 0 {
                    self.complete_strategy.return_too_few_data_n_times -= 1;
                    columns.pop();
                }

                if self
                    .complete_strategy
                    .return_wrong_sidecar_for_block_n_times
                    > 0
                {
                    self.complete_strategy
                        .return_wrong_sidecar_for_block_n_times -= 1;
                    let first = columns.first_mut().expect("empty columns");
                    let column = Arc::make_mut(first);
                    column
                        .signed_block_header_mut()
                        .expect("not fulu")
                        .message
                        .body_root = Hash256::ZERO;
                }
                self.send_rpc_columns_response(req_id, peer_id, &columns);
            }

            (RequestType::BlocksByRange(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.skip_by_range_routes {
                    return;
                }

                // Check if we should disconnect all peers instead of continuing
                if let Some(ref mut remaining) = self
                    .complete_strategy
                    .successful_range_responses_before_disconnect
                {
                    if *remaining == 0 {
                        // Disconnect all peers — remaining responses become "late"
                        for peer in self.get_connected_peers() {
                            self.peer_disconnected(peer);
                        }
                        return;
                    } else {
                        *remaining -= 1;
                    }
                }

                // Return empty response N times to simulate peer returning no blocks
                if self.complete_strategy.return_no_range_blocks_n_times > 0 {
                    self.complete_strategy.return_no_range_blocks_n_times -= 1;
                    self.send_rpc_blocks_response(req_id, peer_id, &[]);
                } else {
                    let blocks = (*req.start_slot()..req.start_slot() + req.count())
                        .filter_map(|slot| {
                            self.network_blocks_by_slot
                                .get(&Slot::new(slot))
                                .map(|block| block.block_cloned())
                        })
                        .collect::<Vec<_>>();
                    self.send_rpc_blocks_response(req_id, peer_id, &blocks);
                }

                // Bring EE back online after N range responses
                if let Some(ref mut remaining) =
                    self.complete_strategy.ee_offline_for_n_range_responses
                {
                    if *remaining == 0 {
                        self.sync_manager
                            .update_execution_engine_state(EngineState::Online);
                        self.complete_strategy.ee_offline_for_n_range_responses = None;
                    } else {
                        *remaining -= 1;
                    }
                }
            }

            (RequestType::BlobsByRange(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.skip_by_range_routes {
                    return;
                }

                // Note: This function is permissive, blocks may have zero blobs and it won't
                // error. Some caveats:
                // - The genesis block never has blobs
                // - Some blocks may not have blobs as the blob count is random
                let blobs = (req.start_slot..req.start_slot + req.count)
                    .filter_map(|slot| self.network_blocks_by_slot.get(&Slot::new(slot)))
                    .filter_map(|block| block.block_data().blobs())
                    .flat_map(|blobs| blobs.into_iter())
                    .collect::<Vec<_>>();
                self.send_rpc_blobs_response(req_id, peer_id, &blobs);
            }

            (RequestType::DataColumnsByRange(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.skip_by_range_routes {
                    return;
                }

                // Return empty columns N times
                if self.complete_strategy.return_no_range_columns_n_times > 0 {
                    self.complete_strategy.return_no_range_columns_n_times -= 1;
                    self.send_rpc_columns_response(req_id, peer_id, &[]);
                    return;
                }

                // Return columns with unrequested indices N times.
                // Note: for supernodes this returns no columns since they custody all indices.
                if self
                    .complete_strategy
                    .return_wrong_range_column_indices_n_times
                    > 0
                {
                    self.complete_strategy
                        .return_wrong_range_column_indices_n_times -= 1;
                    let wrong_columns = (req.start_slot..req.start_slot + req.count)
                        .filter_map(|slot| self.network_blocks_by_slot.get(&Slot::new(slot)))
                        .filter_map(|block| block.block_data().data_columns())
                        .flat_map(|columns| {
                            columns
                                .into_iter()
                                .filter(|c| !req.columns.contains(c.index()))
                        })
                        .collect::<Vec<_>>();
                    self.send_rpc_columns_response(req_id, peer_id, &wrong_columns);
                    return;
                }

                // Return columns from an out-of-range slot N times
                if self
                    .complete_strategy
                    .return_wrong_range_column_slots_n_times
                    > 0
                {
                    self.complete_strategy
                        .return_wrong_range_column_slots_n_times -= 1;
                    // Get a column from a slot AFTER the requested range
                    let wrong_slot = req.start_slot + req.count;
                    let wrong_columns = self
                        .network_blocks_by_slot
                        .get(&Slot::new(wrong_slot))
                        .and_then(|block| block.block_data().data_columns())
                        .into_iter()
                        .flat_map(|columns| {
                            columns
                                .into_iter()
                                .filter(|c| req.columns.contains(c.index()))
                        })
                        .collect::<Vec<_>>();
                    self.send_rpc_columns_response(req_id, peer_id, &wrong_columns);
                    return;
                }

                // Return only half the requested columns N times — triggers CouplingError
                if self.complete_strategy.return_partial_range_columns_n_times > 0 {
                    self.complete_strategy.return_partial_range_columns_n_times -= 1;
                    let columns = (req.start_slot..req.start_slot + req.count)
                        .filter_map(|slot| self.network_blocks_by_slot.get(&Slot::new(slot)))
                        .filter_map(|block| block.block_data().data_columns())
                        .flat_map(|columns| {
                            columns
                                .into_iter()
                                .filter(|c| req.columns.contains(c.index()))
                        })
                        .enumerate()
                        .filter(|(i, _)| i % 2 == 0) // keep every other column
                        .map(|(_, c)| c)
                        .collect::<Vec<_>>();
                    self.send_rpc_columns_response(req_id, peer_id, &columns);
                    return;
                }

                let columns = (req.start_slot..req.start_slot + req.count)
                    .filter_map(|slot| self.network_blocks_by_slot.get(&Slot::new(slot)))
                    .filter_map(|block| block.block_data().data_columns())
                    .flat_map(|columns| {
                        columns
                            .into_iter()
                            .filter(|c| req.columns.contains(c.index()))
                    })
                    .collect::<Vec<_>>();
                self.send_rpc_columns_response(req_id, peer_id, &columns);
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

    fn send_rpc_blobs_response(
        &mut self,
        sync_request_id: SyncRequestId,
        peer_id: PeerId,
        blobs: &[Arc<BlobSidecar<E>>],
    ) {
        let slots = blobs
            .iter()
            .map(|block| block.slot())
            .unique()
            .collect::<Vec<_>>();
        self.log(&format!(
            "Completing request {sync_request_id:?} to {peer_id} with blobs {slots:?}"
        ));

        for blob in blobs {
            self.push_sync_message(SyncMessage::RpcBlob {
                sync_request_id,
                peer_id,
                blob_sidecar: Some(blob.clone()),
                seen_timestamp: D,
            });
        }
        self.push_sync_message(SyncMessage::RpcBlob {
            sync_request_id,
            peer_id,
            blob_sidecar: None,
            seen_timestamp: D,
        });
    }

    fn send_rpc_columns_response(
        &mut self,
        sync_request_id: SyncRequestId,
        peer_id: PeerId,
        columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let slots = columns
            .iter()
            .map(|block| block.slot())
            .unique()
            .collect::<Vec<_>>();
        let indices = columns
            .iter()
            .map(|column| *column.index())
            .unique()
            .collect::<Vec<_>>();
        self.log(&format!(
            "Completing request {sync_request_id:?} to {peer_id} with columns {slots:?} indices {indices:?}"
        ));

        for column in columns {
            self.push_sync_message(SyncMessage::RpcDataColumn {
                sync_request_id,
                peer_id,
                data_column: Some(column.clone()),
                seen_timestamp: D,
            });
        }
        self.push_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id,
            peer_id,
            data_column: None,
            seen_timestamp: D,
        });
    }

    // Preparation steps

    /// Returns the block root of the tip of the built chain
    pub(super) async fn build_chain(&mut self, block_count: usize) -> Hash256 {
        let mut blocks = vec![];

        // Initialise a new beacon chain
        let external_harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(self.harness.spec.clone())
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(self.harness.chain.slot_clock.clone())
            // Make the external harness a supernode so all columns are available
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        // Ensure all blocks have data. Otherwise, the triggers for unknown blob parent and unknown
        // data column parent fail.
        external_harness
            .execution_block_generator()
            .set_min_blob_count(1);

        // Add genesis block for completeness
        let genesis_block = external_harness.get_head_block();
        self.network_blocks_by_root
            .insert(genesis_block.canonical_root(), genesis_block.clone());
        self.network_blocks_by_slot
            .insert(genesis_block.slot(), genesis_block);

        for i in 0..block_count {
            external_harness.advance_slot();
            let block_root = external_harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
            let block = external_harness.get_full_block(&block_root);
            let block_root = block.canonical_root();
            let block_slot = block.slot();
            self.network_blocks_by_root
                .insert(block_root, block.clone());
            self.network_blocks_by_slot.insert(block_slot, block);
            self.log(&format!(
                "Produced block {} index {i} in external harness",
                block_slot,
            ));
            blocks.push((block_slot, block_root));
        }

        // Re-log to have a nice list of block roots at the end
        for block in &blocks {
            self.log(&format!("Build chain {block:?}"));
        }

        // Auto-update the clock on the main harness to accept the blocks
        self.harness
            .set_current_slot(external_harness.get_current_slot());

        blocks.last().expect("empty blocks").1
    }

    fn corrupt_last_block_signature(&mut self) {
        let range_sync_block = self.get_last_block().clone();
        let mut block = (*range_sync_block.block_cloned()).clone();
        let blobs = range_sync_block.block_data().blobs();
        let columns = range_sync_block.block_data().data_columns();
        *block.signature_mut() = self.valid_signature();
        self.re_insert_block(Arc::new(block), blobs, columns);
    }

    fn valid_signature(&mut self) -> bls::Signature {
        let keypair = bls::Keypair::random();
        let msg = Hash256::random();
        keypair.sk.sign(msg)
    }

    fn corrupt_last_blob_proposer_signature(&mut self) {
        let range_sync_block = self.get_last_block().clone();
        let block = range_sync_block.block_cloned();
        let mut blobs = range_sync_block
            .block_data()
            .blobs()
            .expect("no blobs")
            .into_iter()
            .collect::<Vec<_>>();
        let columns = range_sync_block.block_data().data_columns();
        let first = blobs.first_mut().expect("empty blobs");
        Arc::make_mut(first).signed_block_header.signature = self.valid_signature();
        let max_blobs =
            self.harness
                .spec
                .max_blobs_per_block(block.slot().epoch(E::slots_per_epoch())) as usize;
        let blobs =
            types::BlobSidecarList::new(blobs, max_blobs).expect("invalid blob sidecar list");
        self.re_insert_block(block, Some(blobs), columns);
    }

    fn corrupt_last_blob_kzg_proof(&mut self) {
        let range_sync_block = self.get_last_block().clone();
        let block = range_sync_block.block_cloned();
        let mut blobs = range_sync_block
            .block_data()
            .blobs()
            .expect("no blobs")
            .into_iter()
            .collect::<Vec<_>>();
        let columns = range_sync_block.block_data().data_columns();
        let first = blobs.first_mut().expect("empty blobs");
        Arc::make_mut(first).kzg_proof = kzg::KzgProof::empty();
        let max_blobs =
            self.harness
                .spec
                .max_blobs_per_block(block.slot().epoch(E::slots_per_epoch())) as usize;
        let blobs =
            types::BlobSidecarList::new(blobs, max_blobs).expect("invalid blob sidecar list");
        self.re_insert_block(block, Some(blobs), columns);
    }

    fn corrupt_last_column_proposer_signature(&mut self) {
        let range_sync_block = self.get_last_block().clone();
        let block = range_sync_block.block_cloned();
        let blobs = range_sync_block.block_data().blobs();
        let mut columns = range_sync_block
            .block_data()
            .data_columns()
            .expect("no columns");
        let first = columns.first_mut().expect("empty columns");
        Arc::make_mut(first)
            .signed_block_header_mut()
            .expect("not fulu")
            .signature = self.valid_signature();
        self.re_insert_block(block, blobs, Some(columns));
    }

    fn corrupt_last_column_kzg_proof(&mut self) {
        let range_sync_block = self.get_last_block().clone();
        let block = range_sync_block.block_cloned();
        let blobs = range_sync_block.block_data().blobs();
        let mut columns = range_sync_block
            .block_data()
            .data_columns()
            .expect("no columns");
        let first = columns.first_mut().expect("empty columns");
        let column = Arc::make_mut(first);
        let proof = column.kzg_proofs_mut().first_mut().expect("no kzg proofs");
        *proof = kzg::KzgProof::empty();
        self.re_insert_block(block, blobs, Some(columns));
    }

    fn get_last_block(&self) -> &RangeSyncBlock<E> {
        let (_, last_block) = self
            .network_blocks_by_root
            .iter()
            .max_by_key(|(_, block)| block.slot())
            .expect("no blocks");
        last_block
    }

    fn re_insert_block(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
        blobs: Option<types::BlobSidecarList<E>>,
        columns: Option<types::DataColumnSidecarList<E>>,
    ) {
        self.network_blocks_by_slot.clear();
        self.network_blocks_by_root.clear();
        let block_root = block.canonical_root();
        let block_slot = block.slot();
        let block_data = if let Some(columns) = columns {
            AvailableBlockData::new_with_data_columns(columns)
        } else if let Some(blobs) = blobs {
            AvailableBlockData::new_with_blobs(blobs)
        } else {
            AvailableBlockData::NoData
        };
        let range_sync_block = RangeSyncBlock::new(
            block,
            block_data,
            &self.harness.chain.data_availability_checker,
            self.harness.chain.spec.clone(),
        )
        .unwrap();
        self.network_blocks_by_slot
            .insert(block_slot, range_sync_block.clone());
        self.network_blocks_by_root
            .insert(block_root, range_sync_block);
    }

    /// Trigger a lookup with the last created block
    fn trigger_with_last_block(&mut self) {
        let peer_id = match self.fulu_test_type.them_node_custody_type() {
            NodeCustodyType::Fullnode => self.new_connected_peer(),
            NodeCustodyType::Supernode | NodeCustodyType::SemiSupernode => {
                self.new_connected_supernode_peer()
            }
        };
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
        let peer_id = self.new_connected_supernode_peer();
        let block = self.block_at_slot(slot);
        self.trigger_unknown_block_from_attestation(block.canonical_root(), peer_id);
    }

    async fn build_chain_and_trigger_last_block(&mut self, block_count: usize) {
        self.build_chain(block_count).await;
        self.trigger_with_last_block();
    }

    /// Import blocks for slots 1..=up_to_slot into the local chain (advance local head)
    pub(super) async fn import_blocks_up_to_slot(&mut self, up_to_slot: u64) {
        for slot in 1..=up_to_slot {
            let rpc_block = self
                .network_blocks_by_slot
                .get(&Slot::new(slot))
                .unwrap_or_else(|| panic!("No block at slot {slot}"))
                .clone();
            let block_root = rpc_block.canonical_root();
            self.harness
                .chain
                .process_block(
                    block_root,
                    rpc_block,
                    NotifyExecutionLayer::Yes,
                    BlockImportSource::Gossip,
                    || Ok(()),
                )
                .await
                .unwrap();
        }
        self.harness.chain.recompute_head_at_current_slot().await;
    }

    /// Import a block directly into the chain without going through lookup sync
    async fn import_block_by_root(&mut self, block_root: Hash256) {
        let range_sync_block = self
            .network_blocks_by_root
            .get(&block_root)
            .unwrap_or_else(|| panic!("No block for root {block_root}"))
            .clone();

        self.harness
            .chain
            .process_block(
                block_root,
                range_sync_block,
                NotifyExecutionLayer::Yes,
                BlockImportSource::RangeSync,
                || Ok(()),
            )
            .await
            .unwrap();

        self.harness.chain.recompute_head_at_current_slot().await;
    }

    fn trigger_with_last_unknown_block_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let last_block = self.get_last_block().block_cloned();
        self.trigger_unknown_parent_block(peer_id, last_block);
    }

    fn trigger_with_last_unknown_blob_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let blobs = self
            .get_last_block()
            .block_data()
            .blobs()
            .expect("no blobs");
        let blob = blobs.first().expect("empty blobs");
        self.trigger_unknown_parent_blob(peer_id, blob.clone());
    }

    fn trigger_with_last_unknown_data_column_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let columns = self
            .get_last_block()
            .block_data()
            .data_columns()
            .expect("No data columns");
        let column = columns.first().expect("empty columns");
        self.trigger_unknown_parent_column(peer_id, column.clone());
    }

    // Post-test assertions

    pub(super) fn head_slot(&self) -> Slot {
        self.harness.chain.head().head_slot()
    }

    pub(super) fn assert_head_slot(&self, slot: u64) {
        assert_eq!(self.head_slot(), Slot::new(slot), "Unexpected head slot");
    }

    pub(super) fn max_known_slot(&self) -> Slot {
        self.network_blocks_by_slot
            .keys()
            .max()
            .copied()
            .unwrap_or_default()
    }

    pub(super) fn finalized_epoch(&self) -> types::Epoch {
        self.harness
            .chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
    }

    pub(super) fn assert_penalties(&self, expected_penalties: &[&'static str]) {
        let penalties = self
            .penalties
            .iter()
            .map(|penalty| penalty.msg)
            .collect::<Vec<_>>();
        if penalties != expected_penalties {
            panic!(
                "Expected penalties: {:#?} but got {:#?}",
                expected_penalties,
                self.penalties
                    .iter()
                    .map(|p| format!("{} for peer {}", p.msg, p.peer_id))
                    .collect::<Vec<_>>()
            );
        }
    }

    pub(super) fn assert_penalties_of_type(&self, expected_penalty: &'static str) {
        if self.penalties.is_empty() {
            panic!("No penalties but expected some of type {expected_penalty}");
        }
        let non_matching_penalties = self
            .penalties
            .iter()
            .filter(|penalty| penalty.msg != expected_penalty)
            .collect::<Vec<_>>();
        if !non_matching_penalties.is_empty() {
            panic!(
                "Found non-matching penalties to {}: {:?}",
                expected_penalty, non_matching_penalties
            );
        }
    }

    pub(super) fn assert_no_penalties(&mut self) {
        if !self.penalties.is_empty() {
            panic!("Some downscore events: {:?}", self.penalties);
        }
    }
    fn assert_failed_lookup_sync(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.completed_lookups(), 0, "some completed lookups");
        assert_eq!(
            self.dropped_lookups(),
            self.created_lookups(),
            "not all dropped. Current lookups {:?}",
            self.active_single_lookups(),
        );
        self.assert_empty_network();
        self.assert_no_active_lookups();
    }

    fn assert_successful_lookup_sync(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.dropped_lookups(), 0, "some dropped lookups");
        assert_eq!(
            self.completed_lookups(),
            self.created_lookups(),
            "not all lookups completed. Current lookups {:?}",
            self.active_single_lookups(),
        );
        self.assert_empty_network();
        self.assert_no_active_lookups();
    }

    /// There is a lookup created with the block that triggers the unknown message that can't be
    /// completed because it has zero peers
    fn assert_successful_lookup_sync_parent_trigger(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(
            self.completed_lookups() + 1,
            self.created_lookups(),
            "all completed"
        );
        assert_eq!(self.dropped_lookups(), 0, "some dropped lookups");
        self.assert_empty_network();
    }

    fn assert_pending_lookup_sync(&self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.dropped_lookups(), 0, "some dropped lookups");
        assert_eq!(self.completed_lookups(), 0, "some completed lookups");
    }

    /// Assert there is at least one range sync chain created and that all sync chains completed
    pub(super) fn assert_successful_range_sync(&self) {
        assert!(
            self.range_sync_chains_added() > 0,
            "No created range sync chains"
        );
        assert_eq!(
            self.range_sync_chains_added(),
            self.range_sync_chains_removed(),
            "Not all chains completed"
        );
    }

    fn lookup_at_slot(&self, slot: u64) -> &SeenLookup {
        let block_root = self.block_root_at_slot(slot);
        self.seen_lookups
            .values()
            .find(|lookup| lookup.block_root == block_root)
            .unwrap_or_else(|| panic!("No lookup for block_root {block_root} of slot {slot}"))
    }

    fn assert_peers_at_lookup_of_slot(&self, slot: u64, expected_peers: usize) {
        let lookup = self.lookup_at_slot(slot);
        if lookup.seen_peers.len() != expected_peers {
            panic!(
                "Expected lookup of slot {slot} to have {expected_peers} peers but had {:?}",
                lookup.seen_peers
            )
        }
    }

    /// Total count of unique lookups created
    fn created_lookups(&self) -> usize {
        // Subtract initial value to allow resetting metrics mid test
        self.sync_manager.block_lookups().metrics().created_lookups
            - self.initial_block_lookups_metrics.created_lookups
    }

    /// Total count of lookups completed or dropped
    fn dropped_lookups(&self) -> usize {
        // Subtract initial value to allow resetting metrics mid test
        self.sync_manager.block_lookups().metrics().dropped_lookups
            - self.initial_block_lookups_metrics.dropped_lookups
    }

    fn completed_lookups(&self) -> usize {
        // Subtract initial value to allow resetting metrics mid test
        self.sync_manager
            .block_lookups()
            .metrics()
            .completed_lookups
            - self.initial_block_lookups_metrics.completed_lookups
    }

    fn capture_metrics_baseline(&mut self) {
        self.initial_block_lookups_metrics = self.sync_manager.block_lookups().metrics().clone()
    }

    /// Returns the last lookup seen with matching block_root
    fn lookup_by_root(&self, block_root: Hash256) -> &SeenLookup {
        self.seen_lookups
            .values()
            .filter(|lookup| lookup.block_root == block_root)
            .max_by_key(|lookup| lookup.id)
            .unwrap_or_else(|| panic!("No loookup for block_root {block_root}"))
    }

    fn range_sync_chains_added(&self) -> usize {
        self.sync_manager.range_sync().metrics().chains_added
    }

    fn range_sync_chains_removed(&self) -> usize {
        self.sync_manager.range_sync().metrics().chains_removed
    }

    fn custody_columns(&self) -> &[ColumnIndex] {
        self.harness
            .chain
            .data_availability_checker
            .custody_context()
            .custody_columns_for_epoch(None, &self.harness.spec)
    }

    // Test setup

    fn new_after_deneb() -> Option<Self> {
        genesis_fork().deneb_enabled().then(Self::default)
    }

    fn new_after_deneb_before_fulu() -> Option<Self> {
        let fork = genesis_fork();
        if fork.deneb_enabled() && !fork.fulu_enabled() {
            Some(Self::default())
        } else {
            None
        }
    }

    pub fn new_fulu_peer_test(fulu_test_type: FuluTestType) -> Option<Self> {
        genesis_fork().fulu_enabled().then(|| {
            Self::new(TestRigConfig {
                fulu_test_type,
                node_custody_type_override: None,
            })
        })
    }

    pub fn log(&self, msg: &str) {
        info!(msg, "TEST_RIG");
    }

    pub fn is_after_deneb(&self) -> bool {
        self.fork_name.deneb_enabled()
    }

    pub fn is_after_fulu(&self) -> bool {
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

    pub fn send_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.handle_message(sync_message);
    }

    pub fn push_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.send_sync_message(sync_message);
    }

    fn active_single_lookups(&self) -> Vec<BlockLookupSummary> {
        self.sync_manager.block_lookups().active_single_lookups()
    }

    fn active_single_lookups_count(&self) -> usize {
        self.active_single_lookups().len()
    }

    fn assert_single_lookups_count(&self, count: usize) {
        assert_eq!(
            self.active_single_lookups_count(),
            count,
            "Unexpected count of single lookups. Current lookups: {:#?}",
            self.active_single_lookups()
        );
    }

    fn insert_ignored_chain(&mut self, block_root: Hash256) {
        self.log(&format!("Inserting block in ignored chains {block_root:?}"));
        self.sync_manager.insert_ignored_chain(block_root);
    }

    fn assert_ignored_chain(&mut self, chain_hash: Hash256) {
        let chains = self.sync_manager.get_ignored_chains();
        if !chains.contains(&chain_hash) {
            panic!("expected ignored chains to contain {chain_hash:?}: {chains:?}");
        }
    }

    #[track_caller]
    fn assert_no_active_single_lookups(&self) {
        assert!(
            self.active_single_lookups().is_empty(),
            "expect no single block lookups: {:?}",
            self.active_single_lookups()
        );
    }

    #[track_caller]
    fn assert_no_active_lookups(&self) {
        self.assert_no_active_single_lookups();
    }

    pub fn new_connected_peer(&mut self) -> PeerId {
        let key = self.determinstic_key();
        let peer_id = self
            .network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(false, &self.harness.spec, key);

        // Assumes custody subnet count == column count
        let custody_subnets = self
            .network_globals
            .peers
            .read()
            .peer_info(&peer_id)
            .expect("Peer should be known")
            .custody_subnets_iter()
            .copied()
            .collect::<Vec<_>>();
        let peer_custody_str =
            if custody_subnets.len() == self.harness.spec.number_of_custody_groups as usize {
                "all".to_owned()
            } else {
                format!("{custody_subnets:?}")
            };

        self.log(&format!(
            "Added new peer for testing {peer_id:?}, custody: {peer_custody_str}"
        ));
        peer_id
    }

    pub fn new_connected_supernode_peer(&mut self) -> PeerId {
        let key = self.determinstic_key();
        let peer_id = self
            .network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(true, &self.harness.spec, key);
        self.log(&format!(
            "Added new peer for testing {peer_id:?}, custody: supernode"
        ));
        peer_id
    }

    fn determinstic_key(&mut self) -> CombinedKey {
        k256::ecdsa::SigningKey::random(&mut self.rng_08).into()
    }

    pub fn new_connected_peers_for_peerdas(&mut self) -> Vec<PeerId> {
        match self.fulu_test_type.them_node_custody_type() {
            NodeCustodyType::Fullnode => {
                // Enough sampling peers with few columns
                let mut peers = (0..100)
                    .map(|_| self.new_connected_peer())
                    .collect::<Vec<_>>();
                // One supernode peer to ensure all columns have at least one peer
                peers.push(self.new_connected_supernode_peer());
                peers
            }
            NodeCustodyType::Supernode | NodeCustodyType::SemiSupernode => {
                let peer = self.new_connected_supernode_peer();
                vec![peer]
            }
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

    #[allow(dead_code)]
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

    pub fn assert_empty_processor(&mut self) {
        self.drain_processor_rx();
        if !self.beacon_processor_rx_queue.is_empty() {
            panic!(
                "Expected processor to be empty, but has events: {:?}",
                self.beacon_processor_rx_queue
            );
        }
    }

    #[track_caller]
    pub fn assert_empty_network(&mut self) {
        self.drain_network_rx();
        if !self.network_rx_queue.is_empty() {
            let n = self.network_rx_queue.len();
            panic!(
                "expected no network events but got {n} events, displaying first 2: {:#?}",
                self.network_rx_queue[..n.min(2)].iter().collect::<Vec<_>>()
            );
        }
    }

    async fn import_block_to_da_checker(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> AvailabilityProcessingStatus {
        // Simulate importing block from another source. Don't use GossipVerified as it checks with
        // the clock, which does not match the timestamp in the payload.
        let lookup_block = LookupBlock::new(block);
        self.harness
            .chain
            .process_block(
                lookup_block.block_root(),
                lookup_block,
                NotifyExecutionLayer::Yes,
                BlockImportSource::Lookup,
                || Ok(()),
            )
            .await
            .expect("Error processing block")
    }

    async fn insert_block_to_da_chain_and_assert_missing_componens(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) {
        match self.import_block_to_da_checker(block).await {
            AvailabilityProcessingStatus::Imported(_) => {
                panic!("block removed from da_checker, available")
            }
            AvailabilityProcessingStatus::MissingComponents(_, block_root) => {
                self.log(&format!("inserted block to da_checker {block_root:?}"))
            }
        }
    }

    fn insert_blob_to_da_checker(&mut self, blob: Arc<BlobSidecar<E>>) {
        match self
            .harness
            .chain
            .data_availability_checker
            .put_kzg_verified_blobs(
                blob.block_root(),
                std::iter::once(
                    KzgVerifiedBlob::new(blob, &self.harness.chain.kzg, Duration::new(0, 0))
                        .expect("Invalid blob"),
                ),
            )
            .unwrap()
        {
            Availability::Available(_) => panic!("blob removed from da_checker, available"),
            Availability::MissingComponents(block_root) => {
                self.log(&format!("inserted blob to da_checker {block_root:?}"))
            }
        };
    }

    fn insert_block_to_da_checker_as_pre_execution(&mut self, block: Arc<SignedBeaconBlock<E>>) {
        self.log(&format!(
            "Inserting block to availability_cache as pre_execution_block {:?}",
            block.canonical_root()
        ));
        self.harness
            .chain
            .data_availability_checker
            .put_pre_execution_block(block.canonical_root(), block, BlockImportSource::Gossip)
            .unwrap();
    }

    fn simulate_block_gossip_processing_becomes_invalid(&mut self, block_root: Hash256) {
        self.log(&format!(
            "Marking block {block_root:?} in da_checker as execution error"
        ));
        self.harness
            .chain
            .data_availability_checker
            .remove_block_on_execution_error(&block_root);

        self.send_sync_message(SyncMessage::GossipBlockProcessResult {
            block_root,
            imported: false,
        });
    }

    async fn simulate_block_gossip_processing_becomes_valid(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) {
        let block_root = block.canonical_root();

        match self.import_block_to_da_checker(block).await {
            AvailabilityProcessingStatus::Imported(block_root) => {
                self.log(&format!(
                    "insert block to da_checker and it imported {block_root:?}"
                ));
            }
            AvailabilityProcessingStatus::MissingComponents(_, _) => {
                panic!("block not imported after adding to da_checker");
            }
        }

        self.send_sync_message(SyncMessage::GossipBlockProcessResult {
            block_root,
            imported: false,
        });
    }

    fn requests_count(&self) -> HashMap<&'static str, usize> {
        let mut requests_count = HashMap::new();
        for (request, _) in &self.requests {
            *requests_count
                .entry(Into::<&'static str>::into(request))
                .or_default() += 1;
        }
        requests_count
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

macro_rules! run_lookups_tests_for_depths {
    ($($depth:literal),+ $(,)?) => {
        paste::paste! {
            $(
                #[tokio::test]
                async fn [<happy_path_unknown_attestation_depth_ $depth>]() {
                    happy_path_unknown_attestation($depth).await;
                }

                #[tokio::test]
                async fn [<happy_path_unknown_block_parent_depth_ $depth>]() {
                    happy_path_unknown_block_parent($depth).await;
                }

                #[tokio::test]
                async fn [<happy_path_unknown_data_parent_depth_ $depth>]() {
                    happy_path_unknown_data_parent($depth).await;
                }

                #[tokio::test]
                async fn [<happy_path_multiple_triggers_depth_ $depth>]() {
                    happy_path_multiple_triggers($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_empty_block_response_depth_ $depth>]() {
                    bad_peer_empty_block_response($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_empty_data_response_depth_ $depth>]() {
                    bad_peer_empty_data_response($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_too_few_data_response_depth_ $depth>]() {
                    bad_peer_too_few_data_response($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_wrong_block_response_depth_ $depth>]() {
                    bad_peer_wrong_block_response($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_wrong_data_response_depth_ $depth>]() {
                    bad_peer_wrong_data_response($depth).await;
                }

                #[tokio::test]
                async fn [<bad_peer_rpc_failure_depth_ $depth>]() {
                    bad_peer_rpc_failure($depth).await;
                }

                #[tokio::test]
                async fn [<too_many_download_failures_depth_ $depth>]() {
                    too_many_download_failures($depth).await;
                }

                #[tokio::test]
                async fn [<too_many_processing_failures_depth_ $depth>]() {
                    too_many_processing_failures($depth).await;
                }

                #[tokio::test]
                async fn [<peer_disconnected_then_rpc_error_depth_ $depth>]() {
                    peer_disconnected_then_rpc_error($depth).await;
                }
            )+
        }
    };
}

run_lookups_tests_for_depths!(1, 2);

/// Assert that lookup sync succeeds with the happy case
async fn happy_path_unknown_attestation(depth: usize) {
    let mut r = TestRig::default();
    // We get attestation for a block descendant (depth) blocks of current head
    r.build_chain_and_trigger_last_block(depth).await;
    // Complete the request with good peer behaviour
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();
}

async fn happy_path_unknown_block_parent(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain(depth).await;
    r.trigger_with_last_unknown_block_parent();
    r.simulate(SimulateConfig::happy_path()).await;
    // All lookups should NOT complete on this test, however note the following for the tip lookup,
    // it's the lookup for the tip block which has 0 peers and a block cached:
    // - before deneb the block is cached, so it's sent for processing, and success
    // - before fulu the block is cached, but we can't fetch blobs so it's stuck
    // - after fulu the block is cached, we start a custody request and since we use the global pool
    //   of peers we DO have 1 connected synced supernode peer, which gives us the columns and the
    //   lookup succeeds
    if r.is_after_deneb() && !r.is_after_fulu() {
        r.assert_successful_lookup_sync_parent_trigger()
    } else {
        r.assert_successful_lookup_sync();
    }
}

/// Assert that sync completes from a GossipUnknownParentBlob / UnknownDataColumnParent
async fn happy_path_unknown_data_parent(depth: usize) {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain(depth).await;
    if r.is_after_fulu() {
        r.trigger_with_last_unknown_data_column_parent();
    } else if r.is_after_deneb() {
        r.trigger_with_last_unknown_blob_parent();
    }
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync_parent_trigger();
}

/// Assert that multiple trigger types don't create extra lookups
async fn happy_path_multiple_triggers(depth: usize) {
    let mut r = TestRig::default();
    // + 1, because the unknown parent trigger needs two new blocks
    r.build_chain(depth + 1).await;
    r.trigger_with_last_block();
    r.trigger_with_last_block();
    r.trigger_with_last_unknown_block_parent();
    r.trigger_with_last_unknown_block_parent();
    if r.is_after_fulu() {
        r.trigger_with_last_unknown_data_column_parent();
    } else if r.is_after_deneb() {
        r.trigger_with_last_unknown_blob_parent();
    }
    r.simulate(SimulateConfig::happy_path()).await;
    assert_eq!(r.created_lookups(), depth + 1, "Don't create extra lookups");
    r.assert_successful_lookup_sync();
}

// Test bad behaviour of peers

/// Assert that if peer responds with no blocks, we downscore, and retry the same lookup
async fn bad_peer_empty_block_response(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that peer returns empty response once, then good behaviour
    r.simulate(SimulateConfig::new().return_no_blocks_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.assert_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();

    // TODO(tree-sync) For post-deneb assert that the blobs are not re-fetched
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with no blobs / columns, we downscore, and retry the same lookup
async fn bad_peer_empty_data_response(depth: usize) {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::new().return_no_data_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.assert_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with not enough blobs / columns, we downscore, and retry the same
/// lookup
async fn bad_peer_too_few_data_response(depth: usize) {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::new().return_too_few_data_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.assert_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blocks, we downscore, and retry the same lookup
async fn bad_peer_wrong_block_response(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::new().return_wrong_blocks_once())
        .await;
    r.assert_penalties(&["UnrequestedBlockRoot"]);
    r.assert_successful_lookup_sync();

    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blobs / columns, we downscore, and retry the same lookup
async fn bad_peer_wrong_data_response(depth: usize) {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::new().return_wrong_sidecar_for_block_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.assert_penalties(&["UnrequestedBlockRoot"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that on network error, we DON'T downscore, and retry the same lookup
async fn bad_peer_rpc_failure(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(SimulateConfig::new().return_rpc_error(RPCError::UnsupportedProtocol))
        .await;
    r.assert_no_penalties();
    r.assert_successful_lookup_sync();
}

// Test retry logic

/// Assert that on too many download failures the lookup fails, but we can still sync
async fn too_many_download_failures(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that a peer always returns empty
    r.simulate(SimulateConfig::new().return_no_blocks_always())
        .await;
    // We register multiple penalties, the lookup fails and sync does not progress
    r.assert_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.capture_metrics_baseline();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();
}

/// Assert that on too many processing failures the lookup fails, but we can still sync
async fn too_many_processing_failures(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that a peer always returns empty
    r.simulate(
        SimulateConfig::new()
            .with_process_result(|| BlockProcessingResult::Err(BlockError::BlockSlotLimitReached)),
    )
    .await;
    // We register multiple penalties, the lookup fails and sync does not progress
    r.assert_penalties_of_type("lookup_block_processing_failure");
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.capture_metrics_baseline();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();
}

#[tokio::test]
/// Assert that multiple trigger types don't create extra lookups
async fn unknown_parent_does_not_add_peers_to_itself() {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    // 2, because the unknown parent trigger needs two new blocks
    r.build_chain(2).await;
    r.trigger_with_last_unknown_block_parent();
    r.trigger_with_last_unknown_block_parent();
    if r.is_after_fulu() {
        r.trigger_with_last_unknown_data_column_parent();
    } else if r.is_after_deneb() {
        r.trigger_with_last_unknown_blob_parent();
    }
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_peers_at_lookup_of_slot(2, 0);
    r.assert_peers_at_lookup_of_slot(1, 3);
    assert_eq!(r.created_lookups(), 2, "Don't create extra lookups");
    // All lookups should NOT complete on this test, however note the following for the tip lookup,
    // it's the lookup for the tip block which has 0 peers and a block cached:
    // - before fulu the block is cached, but we can't fetch blobs so it's stuck
    // - after fulu the block is cached, we start a custody request and since we use the global pool
    //   of peers we DO have >1 connected synced supernode peer, which gives us the columns and the
    //   lookup succeeds
    if r.is_after_fulu() {
        r.assert_successful_lookup_sync()
    } else {
        r.assert_successful_lookup_sync_parent_trigger();
    }
}

#[tokio::test]
/// Assert that if the beacon processor returns Ignored, the lookup is dropped
async fn test_single_block_lookup_ignored_response() {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(1).await;
    // Send an Ignored response, the request should be dropped
    r.simulate(SimulateConfig::new().with_process_result(|| BlockProcessingResult::Ignored))
        .await;
    // The block was not actually imported
    r.assert_head_slot(0);
    assert_eq!(r.created_lookups(), 1, "no created lookups");
    assert_eq!(r.dropped_lookups(), 1, "no dropped lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
}

#[tokio::test]
/// Assert that if the beacon processor returns DuplicateFullyImported, the lookup completes successfully
async fn test_single_block_lookup_duplicate_response() {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(1).await;
    // Send a DuplicateFullyImported response, the lookup should complete successfully
    r.simulate(SimulateConfig::new().with_process_result(|| {
        BlockProcessingResult::Err(BlockError::DuplicateFullyImported(Hash256::ZERO))
    }))
    .await;
    // The block was not actually imported
    r.assert_head_slot(0);
    r.assert_successful_lookup_sync();
}

/// Assert that when peers disconnect the lookups are not dropped (kept with zero peers)
async fn peer_disconnected_then_rpc_error(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.assert_single_lookups_count(1);
    // The peer disconnect event reaches sync before the rpc error.
    r.disconnect_all_peers();
    // The lookup is not removed as it can still potentially make progress.
    r.assert_single_lookups_count(1);
    r.simulate(SimulateConfig::new().return_rpc_error(RPCError::Disconnected))
        .await;

    // Regardless of depth, only the initial lookup is created, because the peer disconnects before
    // being able to download the block
    assert_eq!(r.created_lookups(), 1, "no created lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
    assert_eq!(r.dropped_lookups(), 0, "some dropped lookups");
    r.assert_empty_network();
    r.assert_single_lookups_count(1);
}

#[tokio::test]
/// Assert that when creating multiple lookups their parent-child relation is discovered and we add
/// peers recursively from child to parent.
async fn lookups_form_chain() {
    let depth = 5;
    let mut r = TestRig::default();
    r.build_chain(depth).await;
    for slot in (1..=depth).rev() {
        r.trigger_with_block_at_slot(slot as u64);
    }
    // TODO(tree-sync): Assert that there are `depth` disjoint chains
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();

    // Assert that the peers are added to ancestor lookups,
    // - The lookup with max slot has 1 peer
    // - The lookup with min slot has all the peers
    for slot in 1..=(depth as u64) {
        let lookup = r.lookup_by_root(r.block_root_at_slot(slot));
        assert_eq!(
            lookup.seen_peers.len(),
            1 + depth - slot as usize,
            "Unexpected peer count for lookup at slot {slot}"
        );
    }
}

#[tokio::test]
/// Assert that if a lookup chain (by appending ancestors) is too long we drop it
async fn test_parent_lookup_too_deep_grow_ancestor_one() {
    let mut r = TestRig::default();
    r.build_chain(PARENT_DEPTH_TOLERANCE + 1).await;
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;

    r.assert_head_slot(PARENT_DEPTH_TOLERANCE as u64 + 1);
    r.assert_no_penalties();
    // Should not penalize peer, but network is not clear because of the blocks_by_range requests
    // r.assert_ignored_chain(chain_hash);
    //
    // Assert that chain is in failed chains
    // Assert that there were 0 lookups completed, 33 dropped
    // Assert that there were 1 range sync chains
    // Bound resources:
    // - Limit amount of requests
    // - Limit the types of sync used
    assert_eq!(r.completed_lookups(), 0, "no completed lookups");
    assert_eq!(
        r.dropped_lookups(),
        PARENT_DEPTH_TOLERANCE,
        "All lookups dropped"
    );
    r.assert_successful_range_sync();
}

#[tokio::test]
async fn test_parent_lookup_too_deep_grow_ancestor_zero() {
    let mut r = TestRig::default();
    r.build_chain(PARENT_DEPTH_TOLERANCE).await;
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;

    r.assert_head_slot(PARENT_DEPTH_TOLERANCE as u64);
    r.assert_no_penalties();
    assert_eq!(
        r.completed_lookups(),
        PARENT_DEPTH_TOLERANCE,
        "completed all lookups"
    );
    assert_eq!(r.dropped_lookups(), 0, "no dropped lookups");
}

// Regression test for https://github.com/sigp/lighthouse/pull/7118
// 8042 UPDATE: block was previously added to the failed_chains cache, now it's inserted into the
// ignored chains cache. The regression test still applies as the child lookup is not created
#[tokio::test]
async fn test_child_lookup_not_created_for_ignored_chain_parent_after_processing() {
    let mut r = TestRig::default();
    let depth = PARENT_DEPTH_TOLERANCE + 1;
    r.build_chain(depth + 1).await;
    r.trigger_with_block_at_slot(depth as u64);
    r.simulate(SimulateConfig::new().no_range_sync()).await;

    // At this point, the chain should have been deemed too deep and pruned.
    // The tip root should have been inserted into ignored chains.
    // Ensure no blocks have been synced
    r.assert_head_slot(0);
    r.assert_no_active_lookups();
    r.assert_no_penalties();
    r.assert_ignored_chain(r.block_at_slot(depth as u64).canonical_root());

    // WHEN: Trigger the extending block that points to the tip.
    let peer = r.new_connected_peer();
    r.trigger_unknown_parent_block(peer, r.block_at_slot(depth as u64 + 1));
    // THEN: The extending block should not create a lookup because the tip was inserted into
    // ignored chains.
    r.assert_no_active_lookups();
    r.assert_no_penalties();
    r.assert_empty_network();
}

#[tokio::test]
/// Assert that if a lookup chain (by appending tips) is too long we drop it
async fn test_parent_lookup_too_deep_grow_tip() {
    let depth = PARENT_DEPTH_TOLERANCE + 1;
    let mut r = TestRig::default();
    r.build_chain(depth).await;
    for slot in (1..=depth).rev() {
        r.trigger_with_block_at_slot(slot as u64);
    }
    r.simulate(SimulateConfig::happy_path()).await;

    // Even if the chain is longer than `PARENT_DEPTH_TOLERANCE` because the lookups are created all
    // at once they chain by sections and it's possible that the oldest ancestors start processing
    // before the full chain is connected.
    assert!(r.created_lookups() > 0, "no created lookups");
    assert_eq!(
        r.completed_lookups(),
        r.created_lookups(),
        "not all completed lookups"
    );
    assert_eq!(r.dropped_lookups(), 0, "some dropped lookups");
    r.assert_successful_lookup_sync();
    // Should not penalize peer, but network is not clear because of the blocks_by_range requests
    r.assert_no_penalties();
}

#[tokio::test]
async fn test_skip_creating_ignored_parent_lookup() {
    let mut r = TestRig::default();
    r.build_chain(2).await;
    r.insert_ignored_chain(r.block_root_at_slot(1));
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_no_penalties();
    // Both current and parent lookup should not be created
    r.assert_no_active_lookups();
}

#[tokio::test]
/// Assert that if the oldest block in a chain is already imported (DuplicateFullyImported),
/// the remaining blocks in the chain are still processed successfully. This tests a race
/// condition where a block gets imported elsewhere while the lookup is processing.
///
/// The processing sequence is:
/// - Block 3: UnknownParent (needs block 2)
/// - Block 2: UnknownParent (needs block 1)
/// - Block 1: About to be processed, but gets imported via gossip (race condition)
/// - Block 1: DuplicateFullyImported (already in chain from race)
/// - Block 2: Import ok (parent block 1 is available)
/// - Block 3: Import ok (parent block 2 is available)
async fn test_same_chain_race_condition() {
    let mut r = TestRig::default();
    r.build_chain(3).await;

    let block_1_root = r.block_root_at_slot(1);

    // Trigger a lookup with block 3. This creates a parent lookup chain that will
    // request blocks 3 → 2 → 1.
    r.trigger_with_block_at_slot(3);

    // Configure simulate to import block 1 right before it's processed by the lookup.
    // This simulates the race condition where block 1 arrives via gossip at the same
    // time the lookup is trying to process it.
    r.simulate(SimulateConfig::new().with_import_block_before_process(block_1_root))
        .await;

    // The chain should complete successfully with head at slot 3, proving that
    // the lookup correctly handled the DuplicateFullyImported for block 1 and
    // continued processing blocks 2 and 3.
    r.assert_head_slot(3);
    r.assert_successful_lookup_sync();
}

#[tokio::test]
/// Assert that if the lookup's block is in the da_checker we don't download it again
async fn block_in_da_checker_skips_download() {
    // Only in Deneb, as the block needs blobs to remain in the da_checker
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    // Add block to da_checker
    // Complete test with happy path
    // Assert that there were no requests for blocks
    r.build_chain(1).await;
    r.insert_block_to_da_chain_and_assert_missing_componens(r.block_at_slot(1))
        .await;
    r.trigger_with_block_at_slot(1);
    r.simulate(SimulateConfig::happy_path()).await;
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

#[tokio::test]
async fn block_in_processing_cache_becomes_invalid() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    r.build_chain(1).await;
    let block = r.block_at_slot(1);
    r.insert_block_to_da_checker_as_pre_execution(block.clone());
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_pending_lookup_sync();
    // Here the only active lookup is waiting for the block to finish processing

    // Simulate invalid block, removing it from processing cache
    r.simulate_block_gossip_processing_becomes_invalid(block.canonical_root());
    // Should download block, then issue blobs request
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_successful_lookup_sync();
}

#[tokio::test]
async fn block_in_processing_cache_becomes_valid_imported() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    r.build_chain(1).await;
    let block = r.block_at_slot(1);
    r.insert_block_to_da_checker_as_pre_execution(block.clone());
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_pending_lookup_sync();
    // Here the only active lookup is waiting for the block to finish processing

    // Resolve the block from processing step
    r.simulate_block_gossip_processing_becomes_valid(block)
        .await;
    // Should not trigger block or blob request
    r.assert_empty_network();
    // Resolve blob and expect lookup completed
    r.assert_no_active_lookups();
}

// IGNORE: wait for change that delays blob fetching to knowing the block
#[tokio::test]
async fn blobs_in_da_checker_skip_download() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    r.build_chain(1).await;
    let block = r.get_last_block().clone();
    let blobs = block.block_data().blobs().expect("block with no blobs");
    for blob in &blobs {
        r.insert_blob_to_da_checker(blob.clone());
    }
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;

    r.assert_successful_lookup_sync();
    assert_eq!(
        r.requests
            .iter()
            .filter(|(request, _)| matches!(request, RequestType::BlobsByRoot(_)))
            .collect::<Vec<_>>(),
        Vec::<&(RequestType<E>, AppRequestId)>::new(),
        "There should be no blob requests"
    );
}

macro_rules! fulu_peer_matrix_tests {
    (
        [$($name:ident => $variant:expr),+ $(,)?]
    ) => {
        paste::paste! {
            $(
                #[tokio::test]
                async fn [<custody_lookup_happy_path _ $name>]() {
                    custody_lookup_happy_path($variant).await;
                }

                #[tokio::test]
                async fn [<custody_lookup_some_custody_failures _ $name>]() {
                    custody_lookup_some_custody_failures($variant).await;
                }

                #[tokio::test]
                async fn [<custody_lookup_permanent_custody_failures _ $name>]() {
                    custody_lookup_permanent_custody_failures($variant).await;
                }
            )+
        }
    };
}

fulu_peer_matrix_tests!(
    [
        we_supernode_them_supernode => FuluTestType::WeSupernodeThemSupernode,
        we_supernode_them_fullnodes => FuluTestType::WeSupernodeThemFullnodes,
        we_fullnode_them_supernode => FuluTestType::WeFullnodeThemSupernode,
        we_fullnode_them_fullnodes => FuluTestType::WeFullnodeThemFullnodes,
    ]
);

async fn custody_lookup_happy_path(test_type: FuluTestType) {
    let Some(mut r) = TestRig::new_fulu_peer_test(test_type) else {
        return;
    };
    r.build_chain(1).await;
    r.new_connected_peers_for_peerdas();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_no_penalties();
    r.assert_successful_lookup_sync();
}

async fn custody_lookup_some_custody_failures(test_type: FuluTestType) {
    let Some(mut r) = TestRig::new_fulu_peer_test(test_type) else {
        return;
    };
    let block_root = r.build_chain(1).await;
    // Send the same trigger from all peers, so that the lookup has all peers
    for peer in r.new_connected_peers_for_peerdas() {
        r.trigger_unknown_block_from_attestation(block_root, peer);
    }
    let custody_columns = r.custody_columns();
    r.simulate(SimulateConfig::new().return_no_columns_on_indices(&custody_columns[..4], 3))
        .await;
    r.assert_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_successful_lookup_sync();
}

async fn custody_lookup_permanent_custody_failures(test_type: FuluTestType) {
    let Some(mut r) = TestRig::new_fulu_peer_test(test_type) else {
        return;
    };
    let block_root = r.build_chain(1).await;

    // Send the same trigger from all peers, so that the lookup has all peers
    for peer in r.new_connected_peers_for_peerdas() {
        r.trigger_unknown_block_from_attestation(block_root, peer);
    }

    let custody_columns = r.custody_columns();
    r.simulate(
        SimulateConfig::new().return_no_columns_on_indices(&custody_columns[..2], usize::MAX),
    )
    .await;
    // Every peer that does not return a column is part of the lookup because it claimed to have
    // imported the lookup, so we will penalize.
    r.assert_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_failed_lookup_sync();
}

// We supernode, diverse peers
// We not supernode, diverse peers

// TODO(das): Test retries of DataColumnByRoot:
// - Expect request for column_index
// - Respond with bad data
// - Respond with stream terminator
//   ^ The stream terminator should be ignored and not close the next retry

// These `crypto_on` tests assert that the fake_crytpo feature works as expected. We run only the
// `crypto_on` tests without the fake_crypto feature and make sure that processing fails, = to
// assert that signatures and kzg proofs are checked
#[tokio::test]
async fn crypto_on_fail_with_invalid_block_signature() {
    let mut r = TestRig::default();
    r.build_chain(1).await;
    r.corrupt_last_block_signature();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    if cfg!(feature = "fake_crypto") {
        r.assert_successful_lookup_sync();
        r.assert_no_penalties();
    } else {
        r.assert_failed_lookup_sync();
        r.assert_penalties_of_type("lookup_block_processing_failure");
    }
}

#[tokio::test]
async fn crypto_on_fail_with_bad_blob_proposer_signature() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    r.build_chain(1).await;
    r.corrupt_last_blob_proposer_signature();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    if cfg!(feature = "fake_crypto") {
        r.assert_successful_lookup_sync();
        r.assert_no_penalties();
    } else {
        r.assert_failed_lookup_sync();
        r.assert_penalties_of_type("lookup_blobs_processing_failure");
    }
}

#[tokio::test]
async fn crypto_on_fail_with_bad_blob_kzg_proof() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
        return;
    };
    r.build_chain(1).await;
    r.corrupt_last_blob_kzg_proof();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    if cfg!(feature = "fake_crypto") {
        r.assert_successful_lookup_sync();
        r.assert_no_penalties();
    } else {
        r.assert_failed_lookup_sync();
        r.assert_penalties_of_type("lookup_blobs_processing_failure");
    }
}

#[tokio::test]
async fn crypto_on_fail_with_bad_column_proposer_signature() {
    let Some(mut r) = TestRig::new_fulu_peer_test(FuluTestType::WeSupernodeThemSupernode) else {
        return;
    };
    r.build_chain(1).await;
    r.corrupt_last_column_proposer_signature();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    if cfg!(feature = "fake_crypto") {
        r.assert_successful_lookup_sync();
        r.assert_no_penalties();
    } else {
        r.assert_failed_lookup_sync();
        r.assert_penalties_of_type("lookup_custody_column_processing_failure");
    }
}

#[tokio::test]
async fn crypto_on_fail_with_bad_column_kzg_proof() {
    let Some(mut r) = TestRig::new_fulu_peer_test(FuluTestType::WeSupernodeThemSupernode) else {
        return;
    };
    r.build_chain(1).await;
    r.corrupt_last_column_kzg_proof();
    r.trigger_with_last_block();
    r.simulate(SimulateConfig::happy_path()).await;
    if cfg!(feature = "fake_crypto") {
        r.assert_successful_lookup_sync();
        r.assert_no_penalties();
    } else {
        r.assert_failed_lookup_sync();
        r.assert_penalties_of_type("lookup_custody_column_processing_failure");
    }
}
