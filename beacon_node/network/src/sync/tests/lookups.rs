use super::*;
use crate::NetworkMessage;
use crate::network_beacon_processor::{InvalidBlockStorage, NetworkBeaconProcessor};
use crate::sync::block_lookups::{BlockLookupSummary, PARENT_DEPTH_TOLERANCE};
use crate::sync::{
    SyncMessage,
    manager::{BlockProcessType, BlockProcessingResult, SyncManager},
};
use itertools::Itertools;
use std::sync::Arc;
use std::time::Duration;

use crate::sync::block_lookups::common::ResponseType;
use beacon_chain::chain_config::TestConfig;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::observed_data_sidecars::Observe;
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, ChainConfig, NotifyExecutionLayer,
    blob_verification::GossipVerifiedBlob,
    block_verification_types::AsBlock,
    data_availability_checker::Availability,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, NumBlobs,
        generate_rand_block_and_blobs, test_spec,
    },
};
use beacon_processor::{BeaconProcessorChannels, DuplicateCache, Work, WorkEvent};
use lighthouse_network::discovery::CombinedKey;
use lighthouse_network::{
    NetworkConfig, NetworkGlobals, PeerId,
    rpc::{RPCError, RequestType},
    service::api_types::{AppRequestId, Id, SingleLookupReqId, SyncRequestId},
    types::SyncState,
};
use slot_clock::{SlotClock, TestingSlotClock};
use tokio::sync::mpsc;
use tracing::info;
use types::{
    BlobSidecar, BlockImportSource, DataColumnSidecar, ForkContext, ForkName, Hash256,
    MinimalEthSpec as E, SignedBeaconBlock, Slot,
    data_column_sidecar::ColumnIndex,
    test_utils::{SeedableRng, XorShiftRng},
};

const D: Duration = Duration::new(0, 0);

/// Instruct the testing rig how to complete requests for _by_range requests
#[derive(Default)]
pub struct CompleteStrategy {
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
    process_result: Option<Box<dyn Fn() -> BlockProcessingResult + Send + Sync>>,
}

impl CompleteStrategy {
    fn new() -> Self {
        Self::default()
    }

    fn happy_path() -> Self {
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

    fn return_rpc_error(mut self, error: RPCError) -> Self {
        self.return_rpc_error = Some(error);
        self
    }

    fn no_range_sync(mut self) -> Self {
        self.skip_by_range_routes = true;
        self
    }

    fn process_result<F>(mut self, f: F) -> Self
    where
        F: Fn() -> BlockProcessingResult + Send + Sync + 'static,
    {
        self.process_result = Some(Box::new(f));
        self
    }
}

fn genesis_fork() -> ForkName {
    test_spec::<E>().fork_name_at_slot::<E>(Slot::new(0))
}

impl TestRig {
    pub fn new(fulu_test_type: FuluTestType) -> Self {
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
            .node_custody_type(fulu_test_type.we_node_custody_type())
            .chain_config(ChainConfig {
                test_config: TestConfig {
                    disable_crypto: true,
                    disable_fetch_blobs: true,
                },
                ..Default::default()
            })
            .build();

        // Initialise a new beacon chain
        let external_harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(spec)
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(clock)
            .chain_config(ChainConfig {
                test_config: TestConfig {
                    disable_crypto: true,
                    disable_fetch_blobs: true,
                },
                ..Default::default()
            }) // Make the external harness a supernode so all columns are available
            .node_custody_type(NodeCustodyType::Supernode)
            .build();
        // Ensure all blocks have data. Otherwise, the triggers for unknown blob parent and unknown
        // data column parent fail.
        external_harness
            .execution_block_generator()
            .set_min_blob_count(1);

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
            network_blocks_by_root,
            network_blocks_by_slot,
            penalties: <_>::default(),
            seen_lookups: <_>::default(),
            requests: <_>::default(),
            complete_strategy: <_>::default(),
            initial_block_lookups_metrics: <_>::default(),
            fulu_test_type,
        }
    }

    pub fn default() -> Self {
        // Before Fulu, FuluTestType is irrelevant
        Self::new(FuluTestType::WeFullnodeThemSupernode)
    }

    // Network / external peers simulated behaviour

    async fn simulate(&mut self, complete_strategy: CompleteStrategy) {
        self.complete_strategy = complete_strategy;

        let mut i = 0;

        loop {
            i += 1;

            // Record current status
            for BlockLookupSummary {
                id,
                block_root,
                peers,
                ..
            } in self.sync_manager.active_single_lookups()
            {
                let lookup = self.seen_lookups.entry(id).or_insert(SeenLookup {
                    id,
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
                    NetworkMessage::ReportPeer { peer_id, msg, .. } => {
                        self.penalties.push(ReportedPenalty { peer_id, msg });
                    }
                    _ => {}
                }
                continue;
            }

            if let Ok(event) = self.beacon_processor_rx.try_recv() {
                self.log(&format!("Tick {i}: beacon_processor event: {event:?}"));
                match event.work {
                    Work::RpcBlock {
                        process_fn,
                        beacon_block_root,
                    } => {
                        if let Some(f) = self.complete_strategy.process_result.as_ref() {
                            let lookup = self.lookup_by_root(beacon_block_root);
                            let result = f();
                            self.log(&format!("Sending custom process result: {result:?}"));
                            self.push_sync_message(SyncMessage::BlockComponentProcessed {
                                process_type: BlockProcessType::SingleBlock { id: lookup.id },
                                result,
                            });
                        } else {
                            process_fn.await
                        }
                    }
                    Work::RpcBlobs { process_fn }
                    | Work::RpcCustodyColumn(process_fn)
                    | Work::ChainSegment(process_fn) => process_fn.await,
                    Work::Reprocess(_) => {} // ignore
                    other => panic!("Unsupported Work event {}", other.str_id()),
                }
                continue;
            }

            break;
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

                let columns_to_omit =
                    if self.complete_strategy.return_no_columns_on_indices_n_times > 0 {
                        self.complete_strategy.return_no_columns_on_indices_n_times -= 1;
                        self.complete_strategy.return_no_columns_on_indices.clone()
                    } else {
                        Vec::new()
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
                            .custody_columns()
                            .unwrap_or_else(|| panic!("Block id {id:?} has no columns"));
                        id.columns
                            .iter()
                            .filter(|index| !columns_to_omit.contains(index))
                            .map(move |index| {
                                block_columns
                                    .iter()
                                    .find(|c| c.index() == *index)
                                    .unwrap_or_else(|| {
                                        panic!("Column {index:?} {:?} not found", id.block_root)
                                    })
                                    .as_data_column()
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
                    let mut column = Arc::make_mut(first).clone();
                    column.signed_block_header.message.body_root = Hash256::ZERO;
                    *first = Arc::new(column);
                }
                self.send_rpc_columns_response(req_id, peer_id, &columns);
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
                    .filter_map(|block| block.blobs())
                    .flat_map(|blobs| blobs.iter().cloned())
                    .collect::<Vec<_>>();
                self.send_rpc_blobs_response(req_id, peer_id, &blobs);
            }

            (RequestType::DataColumnsByRange(req), AppRequestId::Sync(req_id)) => {
                if self.complete_strategy.skip_by_range_routes {
                    return;
                }
                // Note: This function is permissive, blocks may have zero columns and it won't
                // error. Some caveats:
                // - The genesis block never has columns
                // - Some blocks may not have columns as the blob count is random
                let columns = (req.start_slot..req.start_slot + req.count)
                    .filter_map(|slot| self.network_blocks_by_slot.get(&Slot::new(slot)))
                    .filter_map(|block| block.custody_columns())
                    .flat_map(|columns| {
                        columns
                            .iter()
                            .map(|c| c.as_data_column().clone())
                            .filter(|c| req.columns.contains(&c.index))
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
        self.log(&format!(
            "Completing request {sync_request_id:?} to {peer_id} with blobs {slots:?}"
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

    async fn build_chain(&mut self, block_count: usize) {
        let mut blocks = vec![];

        for i in 0..block_count {
            self.external_harness.advance_slot();
            let block_root = self
                .external_harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
            let block = self.external_harness.get_full_block(&block_root);
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

    fn trigger_with_last_unknown_block_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let last_block = self.get_last_block().block_cloned();
        self.trigger_unknown_parent_block(peer_id, last_block);
    }

    fn trigger_with_last_unknown_blob_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let blob = self
            .get_last_block()
            .blobs()
            .expect("no blobs")
            .first()
            .expect("empty blobs");
        self.trigger_unknown_parent_blob(peer_id, blob.clone());
    }

    fn trigger_with_last_unknown_data_column_parent(&mut self) {
        let peer_id = self.new_connected_supernode_peer();
        let column = self
            .get_last_block()
            .custody_columns()
            .expect("No custody columns")
            .first()
            .expect("empty columns");
        self.trigger_unknown_parent_column(peer_id, column.as_data_column().clone());
    }

    // Post-test assertions

    fn head_slot(&self) -> Slot {
        self.harness.chain.head().head_slot()
    }

    fn assert_head_slot(&self, slot: u64) {
        assert_eq!(self.head_slot(), Slot::new(slot), "Unexpected head slot");
    }

    fn max_known_slot(&self) -> Slot {
        self.network_blocks_by_slot
            .keys()
            .max()
            .copied()
            .expect("no blocks")
    }

    fn expect_penalties(&self, expected_penalties: &[&'static str]) {
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

    fn expect_penalties_of_type(&self, expected_penalty: &'static str) {
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

    fn assert_failed_lookup_sync(&mut self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.completed_lookups(), 0, "some completed lookups");
        assert_eq!(
            self.dropped_lookups(),
            self.created_lookups(),
            "not all dropped. Current lookups {:?}",
            self.active_single_lookups(),
        );
        self.expect_empty_network();
        self.expect_no_active_lookups();
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
        self.expect_empty_network();
        self.expect_no_active_lookups();
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
        self.expect_empty_network();
    }

    fn assert_pending_lookup_sync(&self) {
        assert!(self.created_lookups() > 0, "no created lookups");
        assert_eq!(self.dropped_lookups(), 0, "some dropped lookups");
        assert_eq!(self.completed_lookups(), 0, "some completed lookups");
    }

    /// Assert there is at least one range sync chain created and that all sync chains completed
    fn assert_successful_range_sync(&self) {
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
        if lookup.max_seen_peers.len() != expected_peers {
            panic!(
                "Expected lookup of slot {slot} to have {expected_peers} peers but had {:?}",
                lookup.max_seen_peers
            )
        }
    }

    /// Total count of unique lookups created
    fn created_lookups(&self) -> usize {
        // Substract initial value to allow resetting metrics mid test
        self.sync_manager.block_lookups().metrics().created_lookups
            - self.initial_block_lookups_metrics.created_lookups
    }

    /// Total count of lookups completed or dropped
    fn dropped_lookups(&self) -> usize {
        // Substract initial value to allow resetting metrics mid test
        self.sync_manager.block_lookups().metrics().dropped_lookups
            - self.initial_block_lookups_metrics.dropped_lookups
    }

    fn completed_lookups(&self) -> usize {
        // Substract initial value to allow resetting metrics mid test
        self.sync_manager
            .block_lookups()
            .metrics()
            .completed_lookups
            - self.initial_block_lookups_metrics.completed_lookups
    }

    fn reset_metrics(&mut self) {
        self.initial_block_lookups_metrics = self.sync_manager.block_lookups().metrics().clone()
    }

    fn lookup_by_root(&self, block_root: Hash256) -> &SeenLookup {
        self.seen_lookups
            .values()
            .find(|lookup| lookup.block_root == block_root)
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
        if fork.deneb_enabled() && fork.fulu_enabled() {
            Some(Self::default())
        } else {
            None
        }
    }

    pub fn new_fulu_peer_test(fulu_test_type: FuluTestType) -> Option<Self> {
        genesis_fork()
            .fulu_enabled()
            .then(|| Self::new(fulu_test_type))
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

    fn assert_single_lookups_count(&self, count: usize) {
        assert_eq!(
            self.active_single_lookups_count(),
            count,
            "Unexpected count of single lookups. Current lookups: {:#?}",
            self.active_single_lookups()
        );
    }

    fn insert_ignored_chain(&mut self, block_root: Hash256) {
        self.sync_manager.insert_ignored_chain(block_root);
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
            .find(|l| l.block_root == block_root)
            .unwrap_or_else(|| panic!("no single block lookup found for {block_root}"))
            .id
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
        match self.fulu_test_type.them_node_custody_type() {
            NodeCustodyType::Fullnode => {
                // Enough sampling peers with few columns
                for _ in 0..100 {
                    self.new_connected_peer();
                }
                // One supernode peer to ensure all columns have at least one peer
                self.new_connected_supernode_peer();
            }
            NodeCustodyType::Supernode | NodeCustodyType::SemiSupernode => {
                self.new_connected_supernode_peer();
            }
        }
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
                } => Some(format!("{msg} {p_id:?}")),
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

    async fn import_block_to_da_checker(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> AvailabilityProcessingStatus {
        // Simulate importing block from another source. Don't use GossipVerified as it checks with
        // the clock, which does not match the timestamp in the payload.
        let rpc_block = RpcBlock::new_without_blobs(None, block);
        self.harness
            .chain
            .process_block(
                rpc_block.block_root(),
                rpc_block,
                NotifyExecutionLayer::Yes,
                BlockImportSource::Gossip,
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
    r.simulate(CompleteStrategy::happy_path()).await;
    r.assert_successful_lookup_sync();
}

async fn happy_path_unknown_block_parent(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain(depth).await;
    r.trigger_with_last_unknown_block_parent();
    r.simulate(CompleteStrategy::happy_path()).await;
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

/// Assert that sync completes from a GossipUnknownParentBlob / UknownDataColumnParent
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
    r.simulate(CompleteStrategy::happy_path()).await;
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
    r.simulate(CompleteStrategy::happy_path()).await;
    assert_eq!(r.created_lookups(), depth + 1, "Don't create extra lookups");
    r.assert_successful_lookup_sync();
}

// Test bad behaviour of peers

/// Assert that if peer responds with no blocks, we downscore, and retry the same lookup
async fn bad_peer_empty_block_response(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that peer returns empty response once, then good behaviour
    r.simulate(CompleteStrategy::new().return_no_blocks_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
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
    r.simulate(CompleteStrategy::new().return_no_data_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
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
    r.simulate(CompleteStrategy::new().return_too_few_data_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["NotEnoughResponsesReturned"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blocks, we downscore, and retry the same lookup
async fn bad_peer_wrong_block_response(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(CompleteStrategy::new().return_wrong_blocks_once())
        .await;
    r.expect_penalties(&["UnrequestedBlockRoot"]);
    r.assert_successful_lookup_sync();

    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that if peer responds with bad blobs / columns, we downscore, and retry the same lookup
async fn bad_peer_wrong_data_response(depth: usize) {
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(CompleteStrategy::new().return_wrong_sidecar_for_block_once())
        .await;
    // We register a penalty, retry and complete sync successfully
    r.expect_penalties(&["UnrequestedBlockRoot"]);
    r.assert_successful_lookup_sync();
    // TODO(tree-sync) Assert that a single lookup is created (no drops)
}

/// Assert that on network error, we DON'T downscore, and retry the same lookup
async fn bad_peer_rpc_failure(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    r.simulate(CompleteStrategy::new().return_rpc_error(RPCError::UnsupportedProtocol))
        .await;
    r.expect_no_penalties();
    r.assert_successful_lookup_sync();
}

// Test retry logic

/// Assert that on too many download failures the lookup fails, but we can still sync
async fn too_many_download_failures(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that a peer always returns empty
    r.simulate(CompleteStrategy::new().return_no_blocks_always())
        .await;
    // We register multiple penalties, the lookup fails and sync does not progress
    r.expect_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.reset_metrics();
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path()).await;
    r.assert_successful_lookup_sync();
}

/// Assert that on too many processing failures the lookup fails, but we can still sync
async fn too_many_processing_failures(depth: usize) {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(depth).await;
    // Simulate that a peer always returns empty
    r.simulate(
        CompleteStrategy::new()
            .process_result(|| BlockProcessingResult::Err(BlockError::BlockSlotLimitReached)),
    )
    .await;
    // We register multiple penalties, the lookup fails and sync does not progress
    r.expect_penalties_of_type("lookup_block_processing_failure");
    r.assert_failed_lookup_sync();

    // Trigger sync again for same block, and complete successfully.
    // Asserts that the lookup is not on a blacklist
    r.reset_metrics();
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path()).await;
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
    r.simulate(CompleteStrategy::happy_path()).await;
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
/// Assert that if the beacon processor returns Ignored ???
async fn test_single_block_lookup_ignored_response() {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(1).await;
    // Send an Ignored response, the request should be dropped
    r.simulate(CompleteStrategy::new().process_result(|| BlockProcessingResult::Ignored))
        .await;
    // The block was not actually imported
    r.assert_head_slot(0);
    assert_eq!(r.created_lookups(), 1, "no created lookups");
    assert_eq!(r.dropped_lookups(), 1, "no dropped lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
}

#[tokio::test]
/// Assert that if the beacon processor returns Ignored ???
async fn test_single_block_lookup_duplicate_response() {
    let mut r = TestRig::default();
    r.build_chain_and_trigger_last_block(1).await;
    // Send an Ignored response, the request should be dropped
    r.simulate(CompleteStrategy::new().process_result(|| {
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
    r.simulate(CompleteStrategy::new().return_rpc_error(RPCError::Disconnected))
        .await;

    // Regardless of depth, only the initial lookup is created, because the peer disconnects before
    // being able to download the block
    assert_eq!(r.created_lookups(), 1, "no created lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
    assert_eq!(r.dropped_lookups(), 0, "some dropped lookups");
    r.expect_empty_network();
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
    r.simulate(CompleteStrategy::happy_path()).await;
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

#[tokio::test]
/// Assert that if a lookup chain (by appending ancestors) is too long we drop it
async fn test_parent_lookup_too_deep_grow_ancestor_one() {
    let mut r = TestRig::default();
    r.build_chain(PARENT_DEPTH_TOLERANCE + 1).await;
    r.trigger_with_last_block();
    r.simulate(CompleteStrategy::happy_path()).await;

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
    r.simulate(CompleteStrategy::happy_path()).await;

    r.assert_head_slot(PARENT_DEPTH_TOLERANCE as u64);
    r.expect_no_penalties();
    assert_eq!(
        r.completed_lookups(),
        PARENT_DEPTH_TOLERANCE,
        "completed all lookups"
    );
    assert_eq!(r.dropped_lookups(), 0, "no dropped lookups");
}

// Regression test for https://github.com/sigp/lighthouse/pull/7118
// 8042 UPDATE: block was previously added to the failed_chains cache, now it's inserted into the
// ignored chains cache. The regression test still applies as the chaild lookup is not created
#[tokio::test]
async fn test_child_lookup_not_created_for_ignored_chain_parent_after_processing() {
    let mut r = TestRig::default();
    r.build_chain(PARENT_DEPTH_TOLERANCE + 2).await;
    r.trigger_with_block_at_slot(PARENT_DEPTH_TOLERANCE as u64 + 1);
    r.simulate(CompleteStrategy::new().no_range_sync()).await;

    // At this point, the chain should have been deemed too deep and pruned.
    // The tip root should have been inserted into ignored chains.
    // Ensure no blocks have been synced
    r.assert_head_slot(0);
    r.expect_no_active_lookups();
    r.expect_no_penalties();

    // WHEN: Trigger the extending block that points to the tip.
    let peer = r.new_connected_peer();
    r.trigger_unknown_parent_block(peer, r.block_at_slot(PARENT_DEPTH_TOLERANCE as u64 + 2));
    // THEN: The extending block should not create a lookup because the tip was inserted into
    // ignored chains.
    r.expect_no_active_lookups();
    r.expect_no_penalties();
    r.expect_empty_network();
}

#[tokio::test]
/// Assert that if a lookup chain (by appending tips) is too long we drop it
async fn test_parent_lookup_too_deep_grow_tip() {
    let depth = PARENT_DEPTH_TOLERANCE + 1;
    // TODO: Debug why this test fails on phase0
    let Some(mut r) = TestRig::new_after_deneb() else {
        return;
    };
    r.build_chain(depth).await;
    for slot in (1..=depth).rev() {
        r.trigger_with_block_at_slot(slot as u64);
    }
    r.simulate(CompleteStrategy::happy_path()).await;

    assert!(r.created_lookups() > 0, "no created lookups");
    assert_eq!(r.completed_lookups(), 0, "some completed lookups");
    assert_eq!(
        r.dropped_lookups(),
        r.created_lookups(),
        "no dropped lookups"
    );
    r.assert_successful_range_sync();
    // Should not penalize peer, but network is not clear because of the blocks_by_range requests
    r.expect_no_penalties();
    r.assert_ignored_chain(r.block_at_slot(depth as u64).canonical_root());
}

#[test]
fn test_skip_creating_ignored_parent_lookup() {
    let mut rig = TestRig::default();
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
    let mut rig = TestRig::default();

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
    r.simulate(CompleteStrategy::happy_path()).await;
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
    r.simulate(CompleteStrategy::happy_path()).await;
    r.assert_pending_lookup_sync();
    // Here the only active lookup is waiting for the block to finish processing

    // Simulate invalid block, removing it from processing cache
    r.simulate_block_gossip_processing_becomes_invalid(block.canonical_root());
    // Should download block, then issue blobs request
    r.simulate(CompleteStrategy::happy_path()).await;
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
    r.simulate(CompleteStrategy::happy_path()).await;
    r.assert_pending_lookup_sync();
    // Here the only active lookup is waiting for the block to finish processing

    // Resolve the block from processing step
    r.simulate_block_gossip_processing_becomes_valid(block)
        .await;
    // Should not trigger block or blob request
    r.expect_empty_network();
    // Resolve blob and expect lookup completed
    r.expect_no_active_lookups();
}

// IGNORE: wait for change that delays blob fetching to knowing the block
#[ignore]
#[test]
fn blobs_in_da_checker_skip_download() {
    let Some(mut r) = TestRig::new_after_deneb_before_fulu() else {
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
    r.simulate(CompleteStrategy::happy_path()).await;
    r.expect_no_penalties();
    r.assert_successful_lookup_sync();
}

async fn custody_lookup_some_custody_failures(test_type: FuluTestType) {
    let Some(mut r) = TestRig::new_fulu_peer_test(test_type) else {
        return;
    };
    r.build_chain(1).await;
    r.new_connected_peers_for_peerdas();
    r.trigger_with_last_block();

    let custody_columns = r.custody_columns();
    r.simulate(CompleteStrategy::new().return_no_columns_on_indices(&custody_columns[..4], 3))
        .await;
    r.expect_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_successful_lookup_sync();
}

async fn custody_lookup_permanent_custody_failures(test_type: FuluTestType) {
    let Some(mut r) = TestRig::new_fulu_peer_test(test_type) else {
        return;
    };
    r.build_chain(1).await;
    r.new_connected_peers_for_peerdas();
    r.trigger_with_last_block();

    let custody_columns = r.custody_columns();
    r.simulate(
        CompleteStrategy::new().return_no_columns_on_indices(&custody_columns[..4], usize::MAX),
    )
    .await;
    r.expect_penalties_of_type("NotEnoughResponsesReturned");
    r.assert_failed_lookup_sync();
}

// We supernode, diverse peers
// We not supernode, diverse peers

// TODO(das): Test retries of DataColumnByRoot:
// - Expect request for column_index
// - Respond with bad data
// - Respond with stream terminator
//   ^ The stream terminator should be ignored and not close the next retry
