#![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::{
    network_beacon_processor::{
        ChainSegmentProcessId, DuplicateCache, InvalidBlockStorage, NetworkBeaconProcessor,
    },
    service::NetworkMessage,
    sync::{SyncMessage, manager::BlockProcessType},
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::data_column_verification::validate_data_column_sidecar_for_gossip;
use beacon_chain::kzg_utils::blobs_to_data_column_sidecars;
use beacon_chain::observed_data_sidecars::DoNotObserve;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, get_kzg,
    test_spec,
};
use beacon_chain::{BeaconChain, WhenSlotSkipped};
use beacon_processor::{work_reprocessing_queue::*, *};
use gossipsub::MessageAcceptance;
use itertools::Itertools;
use lighthouse_network::rpc::InboundRequestId;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, DataColumnsByRangeRequest, MetaDataV3,
};
use lighthouse_network::{
    Client, MessageId, NetworkConfig, NetworkGlobals, PeerId, Response,
    discv5::enr::{self, CombinedKey},
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield},
};
use matches::assert_matches;
use slot_clock::SlotClock;
use std::collections::HashSet;
use std::iter::Iterator;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::{BlobIdentifier, FixedBlobSidecarList};
use types::{
    AttesterSlashing, BlobSidecar, BlobSidecarList, ChainSpec, DataColumnSidecarList,
    DataColumnSubnetId, Epoch, EthSpec, Hash256, MainnetEthSpec, ProposerSlashing,
    RuntimeVariableList, SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit,
    SingleAttestation, Slot, SubnetId,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const SMALL_CHAIN: u64 = 2;
const LONG_CHAIN: u64 = SLOTS_PER_EPOCH * 2;

const SEQ_NUMBER: u64 = 0;

/// The default time to wait for `BeaconProcessor` events.
const STANDARD_TIMEOUT: Duration = Duration::from_secs(10);

/// Provides utilities for testing the `BeaconProcessor`.
struct TestRig {
    chain: Arc<BeaconChain<T>>,
    next_block: Arc<SignedBeaconBlock<E>>,
    next_blobs: Option<BlobSidecarList<E>>,
    next_data_columns: Option<DataColumnSidecarList<E>>,
    attestations: Vec<(SingleAttestation, SubnetId)>,
    next_block_attestations: Vec<(SingleAttestation, SubnetId)>,
    next_block_aggregate_attestations: Vec<SignedAggregateAndProof<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    beacon_processor_tx: BeaconProcessorSend<E>,
    work_journal_rx: mpsc::Receiver<&'static str>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
    duplicate_cache: DuplicateCache,
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
    _harness: BeaconChainHarness<T>,
}

/// This custom drop implementation ensures that we shut down the tokio runtime gracefully. Without
/// it, tests will hang indefinitely.
impl Drop for TestRig {
    fn drop(&mut self) {
        // Causes the beacon processor to shutdown.
        let len = BeaconProcessorConfig::default().max_work_event_queue_len;
        self.beacon_processor_tx = BeaconProcessorSend(mpsc::channel(len).0);
    }
}

impl TestRig {
    pub async fn new(chain_length: u64) -> Self {
        // This allows for testing voluntary exits without building out a massive chain.
        let mut spec = test_spec::<E>();
        spec.shard_committee_period = 2;
        Self::new_parametric(
            chain_length,
            BeaconProcessorConfig::default(),
            NodeCustodyType::Fullnode,
            spec,
        )
        .await
    }

    pub async fn new_supernode(chain_length: u64) -> Self {
        // This allows for testing voluntary exits without building out a massive chain.
        let mut spec = test_spec::<E>();
        spec.shard_committee_period = 2;
        Self::new_parametric(
            chain_length,
            BeaconProcessorConfig::default(),
            NodeCustodyType::Supernode,
            spec,
        )
        .await
    }

    pub async fn new_parametric(
        chain_length: u64,
        beacon_processor_config: BeaconProcessorConfig,
        node_custody_type: NodeCustodyType,
        spec: ChainSpec,
    ) -> Self {
        let spec = Arc::new(spec);
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec.clone())
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(node_custody_type)
            .chain_config(<_>::default())
            .build();

        harness.advance_slot();

        for _ in 0..chain_length {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;

            harness.advance_slot();
        }

        let head = harness.chain.head_snapshot();

        assert_eq!(
            harness.chain.slot().unwrap(),
            head.beacon_block.slot() + 1,
            "precondition: current slot is one after head"
        );

        // Ensure there is a blob in the next block. Required for some tests.
        harness
            .mock_execution_layer
            .as_ref()
            .unwrap()
            .server
            .execution_block_generator()
            .set_min_blob_count(1);
        let (next_block_tuple, next_state) = harness
            .make_block(head.beacon_state.clone(), harness.chain.slot().unwrap())
            .await;

        let head_state_root = head.beacon_state_root();
        let attestations = harness
            .get_single_attestations(
                &AttestationStrategy::AllValidators,
                &head.beacon_state,
                head_state_root,
                head.beacon_block_root,
                harness.chain.slot().unwrap(),
            )
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        assert!(
            !attestations.is_empty(),
            "precondition: attestations for testing"
        );

        let next_block_attestations = harness
            .get_single_attestations(
                &AttestationStrategy::AllValidators,
                &next_state,
                next_block_tuple.0.state_root(),
                next_block_tuple.0.canonical_root(),
                next_block_tuple.0.slot(),
            )
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let next_block_aggregate_attestations = harness
            .make_attestations(
                &harness.get_all_validators(),
                &next_state,
                next_block_tuple.0.state_root(),
                next_block_tuple.0.canonical_root().into(),
                next_block_tuple.0.slot(),
            )
            .into_iter()
            .filter_map(|(_, aggregate_opt)| aggregate_opt)
            .collect::<Vec<_>>();

        assert!(
            !next_block_attestations.is_empty(),
            "precondition: attestation for next block are not empty"
        );

        let attester_slashing = harness.make_attester_slashing(vec![0, 1]);
        let proposer_slashing = harness.make_proposer_slashing(2);
        let voluntary_exit = harness.make_voluntary_exit(3, harness.chain.epoch().unwrap());

        let chain = harness.chain.clone();

        let (network_tx, network_rx) = mpsc::unbounded_channel();

        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx,
        } = BeaconProcessorChannels::new(&beacon_processor_config);

        let (sync_tx, sync_rx) = mpsc::unbounded_channel();

        // Default metadata
        let meta_data = if spec.is_peer_das_scheduled() {
            MetaData::V3(MetaDataV3 {
                seq_number: SEQ_NUMBER,
                attnets: EnrAttestationBitfield::<MainnetEthSpec>::default(),
                syncnets: EnrSyncCommitteeBitfield::<MainnetEthSpec>::default(),
                custody_group_count: spec.custody_requirement,
            })
        } else {
            MetaData::V2(MetaDataV2 {
                seq_number: SEQ_NUMBER,
                attnets: EnrAttestationBitfield::<MainnetEthSpec>::default(),
                syncnets: EnrSyncCommitteeBitfield::<MainnetEthSpec>::default(),
            })
        };

        let enr_key = CombinedKey::generate_secp256k1();
        let enr = enr::Enr::builder().build(&enr_key).unwrap();
        let network_config = Arc::new(NetworkConfig::default());
        let network_globals = Arc::new(NetworkGlobals::new(
            enr,
            meta_data,
            vec![],
            false,
            network_config,
            spec,
        ));

        let executor = harness.runtime.task_executor.clone();

        let (work_journal_tx, work_journal_rx) = mpsc::channel(16_364);

        let duplicate_cache = DuplicateCache::default();
        let network_beacon_processor = NetworkBeaconProcessor {
            beacon_processor_send: beacon_processor_tx.clone(),
            duplicate_cache: duplicate_cache.clone(),
            chain: harness.chain.clone(),
            network_tx,
            sync_tx,
            network_globals: network_globals.clone(),
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor: executor.clone(),
        };
        let network_beacon_processor = Arc::new(network_beacon_processor);

        let beacon_processor = BeaconProcessor {
            network_globals: network_globals.clone(),
            executor,
            current_workers: 0,
            config: beacon_processor_config,
        }
        .spawn_manager(
            beacon_processor_rx,
            Some(work_journal_tx),
            harness.chain.slot_clock.clone(),
            chain.spec.maximum_gossip_clock_disparity(),
            BeaconProcessorQueueLengths::from_state(
                &chain.canonical_head.cached_head().snapshot.beacon_state,
                &chain.spec,
            )
            .unwrap(),
        );

        assert!(beacon_processor.is_ok());
        let block = next_block_tuple.0;
        let (blob_sidecars, data_columns) = if let Some((kzg_proofs, blobs)) = next_block_tuple.1 {
            if chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
                let kzg = get_kzg(&chain.spec);
                let epoch = block.slot().epoch(E::slots_per_epoch());
                let sampling_indices = chain.sampling_columns_for_epoch(epoch);
                let custody_columns: DataColumnSidecarList<E> = blobs_to_data_column_sidecars(
                    &blobs.iter().collect_vec(),
                    kzg_proofs.clone().into_iter().collect_vec(),
                    &block,
                    &kzg,
                    &chain.spec,
                )
                .unwrap()
                .into_iter()
                .filter(|c| sampling_indices.contains(&c.index))
                .collect::<Vec<_>>();

                (None, Some(custody_columns))
            } else {
                let blob_sidecars =
                    BlobSidecar::build_sidecars(blobs, &block, kzg_proofs, &chain.spec).unwrap();
                (Some(blob_sidecars), None)
            }
        } else {
            (None, None)
        };

        Self {
            chain,
            next_block: block,
            next_blobs: blob_sidecars,
            next_data_columns: data_columns,
            attestations,
            next_block_attestations,
            next_block_aggregate_attestations,
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            beacon_processor_tx,
            work_journal_rx,
            network_rx,
            sync_rx,
            duplicate_cache,
            network_beacon_processor,
            _harness: harness,
        }
    }

    pub async fn recompute_head(&self) {
        self.chain.recompute_head_at_current_slot().await
    }

    pub fn head_root(&self) -> Hash256 {
        self.chain.head_snapshot().beacon_block_root
    }

    pub fn enqueue_gossip_block(&self) {
        self.network_beacon_processor
            .send_gossip_beacon_block(
                junk_message_id(),
                junk_peer_id(),
                Client::default(),
                self.next_block.clone(),
                Duration::from_secs(0),
            )
            .unwrap();
    }

    pub fn enqueue_gossip_blob(&self, blob_index: usize) {
        if let Some(blobs) = self.next_blobs.as_ref() {
            let blob = blobs.get(blob_index).unwrap();
            self.network_beacon_processor
                .send_gossip_blob_sidecar(
                    junk_message_id(),
                    junk_peer_id(),
                    Client::default(),
                    blob.index,
                    blob.clone(),
                    Duration::from_secs(0),
                )
                .unwrap();
        }
    }

    pub fn enqueue_gossip_data_columns(&self, col_index: usize) {
        if let Some(data_columns) = self.next_data_columns.as_ref() {
            let data_column = data_columns.get(col_index).unwrap();
            self.network_beacon_processor
                .send_gossip_data_column_sidecar(
                    junk_message_id(),
                    junk_peer_id(),
                    DataColumnSubnetId::from_column_index(data_column.index, &self.chain.spec),
                    data_column.clone(),
                    Duration::from_secs(0),
                )
                .unwrap();
        }
    }

    pub fn enqueue_rpc_block(&self) {
        let block_root = self.next_block.canonical_root();
        self.network_beacon_processor
            .send_rpc_beacon_block(
                block_root,
                RpcBlock::new_without_blobs(Some(block_root), self.next_block.clone()),
                std::time::Duration::default(),
                BlockProcessType::SingleBlock { id: 0 },
            )
            .unwrap();
    }

    pub fn enqueue_single_lookup_rpc_block(&self) {
        let block_root = self.next_block.canonical_root();
        self.network_beacon_processor
            .send_rpc_beacon_block(
                block_root,
                RpcBlock::new_without_blobs(Some(block_root), self.next_block.clone()),
                std::time::Duration::default(),
                BlockProcessType::SingleBlock { id: 1 },
            )
            .unwrap();
    }

    pub fn enqueue_single_lookup_rpc_blobs(&self) {
        if let Some(blobs) = self.next_blobs.clone() {
            let blobs = FixedBlobSidecarList::new(blobs.into_iter().map(Some).collect::<Vec<_>>());
            self.network_beacon_processor
                .send_rpc_blobs(
                    self.next_block.canonical_root(),
                    blobs,
                    std::time::Duration::default(),
                    BlockProcessType::SingleBlob { id: 1 },
                )
                .unwrap();
        }
    }

    pub fn enqueue_single_lookup_rpc_data_columns(&self) {
        if let Some(data_columns) = self.next_data_columns.clone() {
            self.network_beacon_processor
                .send_rpc_custody_columns(
                    self.next_block.canonical_root(),
                    data_columns,
                    Duration::default(),
                    BlockProcessType::SingleCustodyColumn(1),
                )
                .unwrap();
        }
    }

    pub fn enqueue_blobs_by_range_request(&self, start_slot: u64, count: u64) {
        self.network_beacon_processor
            .send_blobs_by_range_request(
                PeerId::random(),
                InboundRequestId::new_unchecked(42, 24),
                BlobsByRangeRequest { start_slot, count },
            )
            .unwrap();
    }

    pub fn enqueue_blobs_by_root_request(&self, blob_ids: RuntimeVariableList<BlobIdentifier>) {
        self.network_beacon_processor
            .send_blobs_by_roots_request(
                PeerId::random(),
                InboundRequestId::new_unchecked(42, 24),
                BlobsByRootRequest { blob_ids },
            )
            .unwrap();
    }

    pub fn enqueue_data_columns_by_range_request(&self, count: u64, columns: Vec<u64>) {
        self.network_beacon_processor
            .send_data_columns_by_range_request(
                PeerId::random(),
                InboundRequestId::new_unchecked(42, 24),
                DataColumnsByRangeRequest {
                    start_slot: 0,
                    count,
                    columns,
                },
            )
            .unwrap();
    }

    pub fn enqueue_backfill_batch(&self, epoch: Epoch) {
        self.network_beacon_processor
            .send_chain_segment(
                ChainSegmentProcessId::BackSyncBatchId(epoch),
                Vec::default(),
            )
            .unwrap();
    }

    pub fn enqueue_unaggregated_attestation(&self) {
        let (attestation, subnet_id) = self.attestations.first().unwrap().clone();
        self.network_beacon_processor
            .send_unaggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                attestation,
                subnet_id,
                true,
                Duration::from_secs(0),
            )
            .unwrap();
    }

    pub fn enqueue_gossip_attester_slashing(&self) {
        self.network_beacon_processor
            .send_gossip_attester_slashing(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.attester_slashing.clone()),
            )
            .unwrap();
    }

    pub fn enqueue_gossip_proposer_slashing(&self) {
        self.network_beacon_processor
            .send_gossip_proposer_slashing(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.proposer_slashing.clone()),
            )
            .unwrap();
    }

    pub fn enqueue_gossip_voluntary_exit(&self) {
        self.network_beacon_processor
            .send_gossip_voluntary_exit(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.voluntary_exit.clone()),
            )
            .unwrap();
    }

    pub fn enqueue_next_block_unaggregated_attestation(&self) {
        let (attestation, subnet_id) = self.next_block_attestations.first().unwrap().clone();
        self.network_beacon_processor
            .send_unaggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                attestation,
                subnet_id,
                true,
                Duration::from_secs(0),
            )
            .unwrap();
    }

    pub fn enqueue_next_block_aggregated_attestation(&self) {
        let aggregate = self
            .next_block_aggregate_attestations
            .first()
            .unwrap()
            .clone();
        self.network_beacon_processor
            .send_aggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                aggregate,
                Duration::from_secs(0),
            )
            .unwrap();
    }

    /// Assert that the `BeaconProcessor` doesn't produce any events in the given `duration`.
    pub async fn assert_no_events_for(&mut self, duration: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(duration) => (),
            event = self.work_journal_rx.recv() => panic!(
                "received {:?} within {:?} when expecting no events",
                event,
                duration
            ),
        }
    }

    /// Checks that the `BeaconProcessor` event journal contains the `expected` events in the given
    /// order with a matching number of `WORKER_FREED` events in between. `NOTHING_TO_DO` events
    /// are ignored.
    ///
    /// Given the described logic, `expected` must not contain `WORKER_FREED` or `NOTHING_TO_DO`
    /// events.
    pub async fn assert_event_journal_contains_ordered(&mut self, expected: &[WorkType]) {
        let expected = expected
            .iter()
            .map(|ev| ev.into())
            .collect::<Vec<&'static str>>();

        let mut events = Vec::with_capacity(expected.len());
        let mut worker_freed_remaining = expected.len();

        let drain_future = async {
            loop {
                match self.work_journal_rx.recv().await {
                    Some(event) if event == WORKER_FREED => {
                        worker_freed_remaining -= 1;
                        if worker_freed_remaining == 0 {
                            // Break when all expected events are finished.
                            break;
                        }
                    }
                    Some(event) if event == NOTHING_TO_DO => {
                        // Ignore these.
                    }
                    Some(event) => {
                        events.push(event);
                    }
                    None => break,
                }
            }
        };

        // Drain the expected number of events from the channel, or time out and give up.
        tokio::select! {
            _ = tokio::time::sleep(STANDARD_TIMEOUT) => panic!(
                "Timeout ({:?}) expired waiting for events. Expected {:?} but got {:?} waiting for {} `WORKER_FREED` events.",
                STANDARD_TIMEOUT,
                expected,
                events,
                worker_freed_remaining,
            ),
            _ = drain_future => {},
        }

        assert_eq!(events, expected);
        assert_eq!(worker_freed_remaining, 0);
    }

    pub async fn assert_event_journal(&mut self, expected: &[&str]) {
        self.assert_event_journal_with_timeout(expected, STANDARD_TIMEOUT, false, false)
            .await
    }

    pub async fn assert_event_journal_completes_with_timeout(
        &mut self,
        expected: &[WorkType],
        timeout: Duration,
    ) {
        self.assert_event_journal_with_timeout(
            &expected
                .iter()
                .map(Into::<&'static str>::into)
                .chain(std::iter::once(WORKER_FREED))
                .chain(std::iter::once(NOTHING_TO_DO))
                .collect::<Vec<_>>(),
            timeout,
            false,
            false,
        )
        .await
    }

    pub async fn assert_event_journal_does_not_complete_with_timeout(
        &mut self,
        expected: &[WorkType],
        timeout: Duration,
    ) {
        self.assert_not_in_event_journal_with_timeout(
            &expected
                .iter()
                .map(Into::<&'static str>::into)
                .chain(std::iter::once(WORKER_FREED))
                .chain(std::iter::once(NOTHING_TO_DO))
                .collect::<Vec<_>>(),
            timeout,
        )
        .await
    }

    pub async fn assert_event_journal_completes(&mut self, expected: &[WorkType]) {
        self.assert_event_journal(
            &expected
                .iter()
                .map(Into::<&'static str>::into)
                .chain(std::iter::once(WORKER_FREED))
                .chain(std::iter::once(NOTHING_TO_DO))
                .collect::<Vec<_>>(),
        )
        .await
    }

    /// Assert that the `BeaconProcessor` event journal is as `expected`.
    ///
    /// ## Note
    ///
    /// We won't attempt to listen for any more than `expected.len()` events. As such, it makes sense
    /// to use the `NOTHING_TO_DO` event to ensure that execution has completed.
    pub async fn assert_event_journal_with_timeout(
        &mut self,
        expected: &[&str],
        timeout: Duration,
        ignore_worker_freed: bool,
        ignore_nothing_to_do: bool,
    ) {
        let mut events = Vec::with_capacity(expected.len());

        let drain_future = async {
            while let Some(event) = self.work_journal_rx.recv().await {
                if event == WORKER_FREED && ignore_worker_freed {
                    continue;
                }

                if event == NOTHING_TO_DO && ignore_nothing_to_do {
                    continue;
                }

                events.push(event);

                // Break as soon as we collect the desired number of events.
                if events.len() >= expected.len() {
                    break;
                }
            }
        };

        // Drain the expected number of events from the channel, or time out and give up.
        tokio::select! {
            _ = tokio::time::sleep(timeout) => panic!(
                "Timeout ({:?}) expired waiting for events. Expected {:?} but got {:?}",
                timeout,
                expected,
                events
            ),
            _ = drain_future => {},
        }

        assert_eq!(events, expected);
    }

    /// Assert that the `BeaconProcessor` event journal is not as `expected`.
    pub async fn assert_not_in_event_journal_with_timeout(
        &mut self,
        expected: &[&str],
        timeout: Duration,
    ) {
        let mut events = Vec::with_capacity(expected.len());

        let drain_future = async {
            while let Some(event) = self.work_journal_rx.recv().await {
                events.push(event);

                // Break as soon as we collect the desired number of events.
                if events.len() >= expected.len() {
                    break;
                }
            }
        };

        // Panic if we don't time out.
        tokio::select! {
            _ = tokio::time::sleep(timeout) => {},
            _ = drain_future =>  panic!(
                "Got events before timeout. Expected no events but got {:?}",
                events
            ),
        }

        assert_ne!(events, expected);
    }

    /// Listen for network messages and collect them for a specified duration or until reaching a count.
    ///
    /// Returns None if no messages were received, or Some(Vec) containing the received messages.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum duration to listen for messages
    /// * `count` - Optional maximum number of messages to collect before returning
    pub async fn receive_network_messages_with_timeout(
        &mut self,
        timeout: Duration,
        count: Option<usize>,
    ) -> Option<Vec<NetworkMessage<E>>> {
        let mut events = vec![];

        let timeout_future = tokio::time::sleep(timeout);
        tokio::pin!(timeout_future);

        loop {
            // Break if we've received the requested count of messages
            if let Some(target_count) = count
                && events.len() >= target_count
            {
                break;
            }

            tokio::select! {
                _ = &mut timeout_future => break,
                maybe_msg = self.network_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => events.push(msg),
                        None => break, // Channel closed
                    }
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Listen for sync messages and collect them for a specified duration or until reaching a count.
    ///
    /// Returns None if no messages were received, or Some(Vec) containing the received messages.
    pub async fn receive_sync_messages_with_timeout(
        &mut self,
        timeout: Duration,
        count: Option<usize>,
    ) -> Option<Vec<SyncMessage<E>>> {
        let mut events = vec![];

        let timeout_future = tokio::time::sleep(timeout);
        tokio::pin!(timeout_future);

        loop {
            // Break if we've received the requested count of messages
            if let Some(target_count) = count
                && events.len() >= target_count
            {
                break;
            }

            tokio::select! {
                _ = &mut timeout_future => break,
                maybe_msg = self.sync_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => events.push(msg),
                        None => break, // Channel closed
                    }
                }
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }
}

fn junk_peer_id() -> PeerId {
    PeerId::random()
}

fn junk_message_id() -> MessageId {
    MessageId::new(&[])
}

// Test that column reconstruction is delayed for columns that arrive
// at the beginning of the slot.
#[tokio::test]
async fn data_column_reconstruction_at_slot_start() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new_supernode(SMALL_CHAIN).await;

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - rig.chain.spec.maximum_gossip_clock_disparity());

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    for i in 0..num_data_columns {
        rig.enqueue_gossip_data_columns(i);
        rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
            .await;
    }

    if num_data_columns > 0 {
        // Reconstruction is delayed by 100ms, we should not be able to complete
        // reconstruction up to this point
        rig.assert_event_journal_does_not_complete_with_timeout(
            &[WorkType::ColumnReconstruction],
            Duration::from_millis(100),
        )
        .await;

        // We've waited at least 150ms, reconstruction can now be triggered
        rig.assert_event_journal_completes_with_timeout(
            &[WorkType::ColumnReconstruction],
            Duration::from_millis(200),
        )
        .await;
    }
}

// Test that column reconstruction happens immediately for columns that arrive at the
// reconstruction deadline.
#[tokio::test]
async fn data_column_reconstruction_at_deadline() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new_supernode(SMALL_CHAIN).await;

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - rig.chain.spec.maximum_gossip_clock_disparity());

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    // We push the slot clock to 3 seconds into the slot, this is the deadline to trigger reconstruction.
    rig.chain
        .slot_clock
        .set_current_time(slot_start + Duration::from_secs(3));

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    for i in 0..num_data_columns {
        rig.enqueue_gossip_data_columns(i);
        rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
            .await;
    }

    // Since we're at the reconstruction deadline, reconstruction should be triggered immediately
    if num_data_columns > 0 {
        rig.assert_event_journal_completes_with_timeout(
            &[WorkType::ColumnReconstruction],
            Duration::from_millis(50),
        )
        .await;
    }
}

// Test the column reconstruction is delayed for columns that arrive for a previous slot.
#[tokio::test]
async fn data_column_reconstruction_at_next_slot() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new_supernode(SMALL_CHAIN).await;

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - rig.chain.spec.maximum_gossip_clock_disparity());

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    // We push the slot clock to the next slot.
    rig.chain
        .slot_clock
        .set_current_time(slot_start + Duration::from_secs(12));

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    for i in 0..num_data_columns {
        rig.enqueue_gossip_data_columns(i);
        rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
            .await;
    }

    if num_data_columns > 0 {
        // Since we are in the next slot reconstruction for the previous slot should be delayed again
        rig.assert_event_journal_does_not_complete_with_timeout(
            &[WorkType::ColumnReconstruction],
            Duration::from_millis(100),
        )
        .await;

        // We've waited at least 150ms, reconstruction can now be triggered
        rig.assert_event_journal_completes_with_timeout(
            &[WorkType::ColumnReconstruction],
            Duration::from_millis(200),
        )
        .await;
    }
}

/// Blocks that arrive early should be queued for later processing.
#[tokio::test]
async fn import_gossip_block_acceptably_early() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - rig.chain.spec.maximum_gossip_clock_disparity());

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal_completes(&[WorkType::GossipBlock])
        .await;

    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    for i in 0..num_blobs {
        rig.enqueue_gossip_blob(i);
        rig.assert_event_journal_completes(&[WorkType::GossipBlobSidecar])
            .await;
    }

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    for i in 0..num_data_columns {
        rig.enqueue_gossip_data_columns(i);
        rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
            .await;
    }

    // Note: this section of the code is a bit race-y. We're assuming that we can set the slot clock
    // and check the head in the time between the block arrived early and when its due for
    // processing.
    //
    // If this causes issues we might be able to make the block delay queue add a longer delay for
    // processing, instead of just ADDITIONAL_QUEUED_BLOCK_DELAY. Speak to @paulhauner if this test
    // starts failing.
    rig.chain.slot_clock.set_slot(rig.next_block.slot().into());

    assert!(
        rig.head_root() != rig.next_block.canonical_root(),
        "block not yet imported"
    );

    rig.assert_event_journal_completes(&[WorkType::DelayedImportBlock])
        .await;

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}

/// Blocks that are *too* early shouldn't get into the delay queue.
#[tokio::test]
async fn import_gossip_block_unacceptably_early() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain.slot_clock.set_current_time(
        slot_start - rig.chain.spec.maximum_gossip_clock_disparity() - Duration::from_millis(1),
    );

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal_completes(&[WorkType::GossipBlock])
        .await;

    // Waiting for 5 seconds is a bit arbitrary, however it *should* be long enough to ensure the
    // block isn't imported.
    rig.assert_no_events_for(Duration::from_secs(5)).await;

    assert!(
        rig.head_root() != rig.next_block.canonical_root(),
        "block should not be imported"
    );
}

/// Data columns that have already been processed but unobserved should be propagated without re-importing.
#[tokio::test]
async fn accept_processed_gossip_data_columns_without_import() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new(SMALL_CHAIN).await;

    // GIVEN the data columns have already been processed but unobserved.
    // 1. verify data column with `DoNotObserve` to create verified but unobserved data columns.
    // 2. put verified but unobserved data columns into the data availability cache.
    let verified_data_columns: Vec<_> = rig
        .next_data_columns
        .clone()
        .unwrap()
        .into_iter()
        .map(|data_column| {
            let subnet_id =
                DataColumnSubnetId::from_column_index(data_column.index, &rig.chain.spec);
            validate_data_column_sidecar_for_gossip::<_, DoNotObserve>(
                data_column,
                subnet_id,
                &rig.chain,
            )
            .expect("should be valid data column")
        })
        .collect();

    let block_root = rig.next_block.canonical_root();
    rig.chain
        .data_availability_checker
        .put_gossip_verified_data_columns(block_root, rig.next_block.slot(), verified_data_columns)
        .expect("should put data columns into availability cache");

    // WHEN an already processed but unobserved data column is received via gossip
    rig.enqueue_gossip_data_columns(0);

    // THEN the data column should be propagated without re-importing (not sure if there's an easy way to test this)
    let network_message = rig
        .receive_network_messages_with_timeout(Duration::from_millis(100), Some(1))
        .await
        .and_then(|mut vec| vec.pop())
        .expect("should receive network messages");

    assert_matches!(
        network_message,
        NetworkMessage::ValidationResult {
            propagation_source: _,
            message_id: _,
            validation_result: MessageAcceptance::Accept,
        }
    );
}

/// Blocks that arrive on-time should be processed normally.
#[tokio::test]
async fn import_gossip_block_at_current_slot() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot(),
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal_completes(&[WorkType::GossipBlock])
        .await;

    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    for i in 0..num_blobs {
        rig.enqueue_gossip_blob(i);
        rig.assert_event_journal_completes(&[WorkType::GossipBlobSidecar])
            .await;
    }

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    for i in 0..num_data_columns {
        rig.enqueue_gossip_data_columns(i);
        rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
            .await;
    }

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}

/// Ensure a valid attestation can be imported.
#[tokio::test]
async fn import_gossip_attestation() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_unaggregated_attestation();

    rig.assert_event_journal_completes(&[WorkType::GossipAttestation])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns + 1,
        "op pool should have one more attestation"
    );
}

enum BlockImportMethod {
    Gossip,
    Rpc,
}

/// Ensure that attestations that reference an unknown block get properly re-queued and
/// re-processed upon importing the block.
async fn attestation_to_unknown_block_processed(import_method: BlockImportMethod) {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_next_block_unaggregated_attestation();

    rig.assert_event_journal_completes(&[WorkType::GossipAttestation])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.
    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    let mut events = vec![];
    match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            events.push(WorkType::GossipBlock);
            for i in 0..num_blobs {
                rig.enqueue_gossip_blob(i);
                events.push(WorkType::GossipBlobSidecar);
            }
            for i in 0..num_data_columns {
                rig.enqueue_gossip_data_columns(i);
                events.push(WorkType::GossipDataColumnSidecar);
            }
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            events.push(WorkType::RpcBlock);
            if num_blobs > 0 {
                rig.enqueue_single_lookup_rpc_blobs();
                events.push(WorkType::RpcBlobs);
            }
            if num_data_columns > 0 {
                rig.enqueue_single_lookup_rpc_data_columns();
                events.push(WorkType::RpcCustodyColumn);
            }
        }
    };

    events.push(WorkType::UnknownBlockAttestation);

    rig.assert_event_journal_contains_ordered(&events).await;

    // Run fork choice, since it isn't run when processing an RPC block. At runtime it is the
    // responsibility of the sync manager to do this.
    rig.recompute_head().await;

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "Block should be imported and become head."
    );

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns + 1,
        "Attestation should have been included."
    );
}

#[tokio::test]
async fn attestation_to_unknown_block_processed_after_gossip_block() {
    attestation_to_unknown_block_processed(BlockImportMethod::Gossip).await
}

#[tokio::test]
async fn attestation_to_unknown_block_processed_after_rpc_block() {
    attestation_to_unknown_block_processed(BlockImportMethod::Rpc).await
}

/// Ensure that attestations that reference an unknown block get properly re-queued and
/// re-processed upon importing the block.
async fn aggregate_attestation_to_unknown_block(import_method: BlockImportMethod) {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    // Empty the op pool.
    rig.chain.op_pool.prune_attestations(u64::MAX.into());
    assert_eq!(rig.chain.op_pool.num_attestations(), 0);

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.op_pool.num_attestations();

    rig.enqueue_next_block_aggregated_attestation();

    rig.assert_event_journal_completes(&[WorkType::GossipAggregate])
        .await;

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.
    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    let mut events = vec![];
    match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            events.push(WorkType::GossipBlock);
            for i in 0..num_blobs {
                rig.enqueue_gossip_blob(i);
                events.push(WorkType::GossipBlobSidecar);
            }
            for i in 0..num_data_columns {
                rig.enqueue_gossip_data_columns(i);
                events.push(WorkType::GossipDataColumnSidecar)
            }
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            events.push(WorkType::RpcBlock);
            if num_blobs > 0 {
                rig.enqueue_single_lookup_rpc_blobs();
                events.push(WorkType::RpcBlobs);
            }
            if num_data_columns > 0 {
                rig.enqueue_single_lookup_rpc_data_columns();
                events.push(WorkType::RpcCustodyColumn);
            }
        }
    };

    events.push(WorkType::UnknownBlockAggregate);

    rig.assert_event_journal_contains_ordered(&events).await;

    // Run fork choice, since it isn't run when processing an RPC block. At runtime it is the
    // responsibility of the sync manager to do this.
    rig.recompute_head().await;

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "Block should be imported and become head."
    );

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns + 1,
        "Attestation should have been included."
    );
}

#[tokio::test]
async fn aggregate_attestation_to_unknown_block_processed_after_gossip_block() {
    aggregate_attestation_to_unknown_block(BlockImportMethod::Gossip).await
}

#[tokio::test]
async fn aggregate_attestation_to_unknown_block_processed_after_rpc_block() {
    aggregate_attestation_to_unknown_block(BlockImportMethod::Rpc).await
}

/// Ensure that attestations that reference an unknown block get properly re-queued and re-processed
/// when the block is not seen.
#[tokio::test]
async fn requeue_unknown_block_gossip_attestation_without_import() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_next_block_unaggregated_attestation();

    rig.assert_event_journal_completes(&[WorkType::GossipAttestation])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[
            WorkType::UnknownBlockAttestation.into(),
            WORKER_FREED,
            NOTHING_TO_DO,
        ],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
        false,
        false,
    )
    .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );
}

/// Ensure that aggregate that reference an unknown block get properly re-queued and re-processed
/// when the block is not seen.
#[tokio::test]
async fn requeue_unknown_block_gossip_aggregated_attestation_without_import() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.op_pool.num_attestations();

    rig.enqueue_next_block_aggregated_attestation();

    rig.assert_event_journal_completes(&[WorkType::GossipAggregate])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[
            WorkType::UnknownBlockAggregate.into(),
            WORKER_FREED,
            NOTHING_TO_DO,
        ],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
        false,
        false,
    )
    .await;

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns,
        "Attestation should not have been included."
    );
}

/// Ensure a bunch of valid operations can be imported.
#[tokio::test]
async fn import_misc_gossip_ops() {
    // Exits need the long chain so validators aren't too young to exit.
    let mut rig = TestRig::new(LONG_CHAIN).await;

    /*
     * Attester slashing
     */

    let initial_attester_slashings = rig.chain.op_pool.num_attester_slashings();

    rig.enqueue_gossip_attester_slashing();

    rig.assert_event_journal_completes(&[WorkType::GossipAttesterSlashing])
        .await;

    assert_eq!(
        rig.chain.op_pool.num_attester_slashings(),
        initial_attester_slashings + 1,
        "op pool should have one more attester slashing"
    );

    /*
     * Proposer slashing
     */

    let initial_proposer_slashings = rig.chain.op_pool.num_proposer_slashings();

    rig.enqueue_gossip_proposer_slashing();

    rig.assert_event_journal_completes(&[WorkType::GossipProposerSlashing])
        .await;

    assert_eq!(
        rig.chain.op_pool.num_proposer_slashings(),
        initial_proposer_slashings + 1,
        "op pool should have one more proposer slashing"
    );

    /*
     * Voluntary exit
     */

    let initial_voluntary_exits = rig.chain.op_pool.num_voluntary_exits();

    rig.enqueue_gossip_voluntary_exit();

    rig.assert_event_journal_completes(&[WorkType::GossipVoluntaryExit])
        .await;

    assert_eq!(
        rig.chain.op_pool.num_voluntary_exits(),
        initial_voluntary_exits + 1,
        "op pool should have one more exit"
    );
}

/// Ensure that rpc block going to the reprocessing queue flow
/// works when the duplicate cache handle is held by another task.
#[tokio::test]
async fn test_rpc_block_reprocessing() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;
    let next_block_root = rig.next_block.canonical_root();
    // Insert the next block into the duplicate cache manually
    let handle = rig.duplicate_cache.check_and_insert(next_block_root);
    rig.enqueue_single_lookup_rpc_block();
    rig.assert_event_journal_completes(&[WorkType::RpcBlock])
        .await;

    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    if num_blobs > 0 {
        rig.enqueue_single_lookup_rpc_blobs();
        rig.assert_event_journal_completes(&[WorkType::RpcBlobs])
            .await;
    }

    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    if num_data_columns > 0 {
        rig.enqueue_single_lookup_rpc_data_columns();
        rig.assert_event_journal_completes(&[WorkType::RpcCustodyColumn])
            .await;
    }

    // next_block shouldn't be processed since it couldn't get the
    // duplicate cache handle
    assert_ne!(next_block_root, rig.head_root());

    drop(handle);

    // The block should arrive at the beacon processor again after
    // the specified delay.
    tokio::time::sleep(QUEUED_RPC_BLOCK_DELAY).await;

    rig.assert_event_journal(&[WorkType::RpcBlock.into()]).await;

    let max_retries = 3;
    let mut success = false;
    for _ in 0..max_retries {
        // Add an extra delay for block processing
        tokio::time::sleep(Duration::from_millis(10)).await;
        // head should update to the next block now since the duplicate
        // cache handle was dropped.
        if next_block_root == rig.head_root() {
            success = true;
            break;
        }
    }
    assert!(
        success,
        "expected head_root to be {:?} but was {:?}",
        next_block_root,
        rig.head_root()
    );
}

/// Ensure that backfill batches get rate-limited and processing is scheduled at specified intervals.
#[tokio::test]
async fn test_backfill_sync_processing() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;
    // Note: to verify the exact event times in an integration test is not straight forward here
    // (not straight forward to manipulate `TestingSlotClock` due to cloning of `SlotClock` in code)
    // and makes the test very slow, hence timing calculation is unit tested separately in
    // `work_reprocessing_queue`.
    for i in 0..1 {
        rig.enqueue_backfill_batch(Epoch::new(i));
        // ensure queued batch is not processed until later
        rig.assert_no_events_for(Duration::from_millis(100)).await;
        // A new batch should be processed within a slot.
        rig.assert_event_journal_with_timeout(
            &[
                WorkType::ChainSegmentBackfill.into(),
                WORKER_FREED,
                NOTHING_TO_DO,
            ],
            rig.chain.slot_clock.slot_duration(),
            false,
            false,
        )
        .await;
    }
}

/// Ensure that backfill batches get processed as fast as they can when rate-limiting is disabled.
#[tokio::test]
async fn test_backfill_sync_processing_rate_limiting_disabled() {
    let beacon_processor_config = BeaconProcessorConfig {
        enable_backfill_rate_limiting: false,
        ..Default::default()
    };
    let mut rig = TestRig::new_parametric(
        SMALL_CHAIN,
        beacon_processor_config,
        NodeCustodyType::Fullnode,
        test_spec::<E>(),
    )
    .await;

    for i in 0..3 {
        rig.enqueue_backfill_batch(Epoch::new(i));
    }

    // ensure all batches are processed
    rig.assert_event_journal_with_timeout(
        &[
            WorkType::ChainSegmentBackfill.into(),
            WorkType::ChainSegmentBackfill.into(),
            WorkType::ChainSegmentBackfill.into(),
        ],
        Duration::from_millis(100),
        true,
        true,
    )
    .await;
}

#[tokio::test]
async fn test_blobs_by_range() {
    if test_spec::<E>().deneb_fork_epoch.is_none() {
        return;
    };
    let mut rig = TestRig::new(64).await;
    let start_slot = 0;
    let slot_count = 32;
    rig.enqueue_blobs_by_range_request(start_slot, slot_count);

    let mut blob_count = 0;
    for slot in 0..slot_count {
        let root = rig
            .chain
            .block_root_at_slot(Slot::new(slot), WhenSlotSkipped::None)
            .unwrap();
        blob_count += root
            .map(|root| {
                rig.chain
                    .get_blobs(&root)
                    .map(|list| list.len())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
    }
    let mut actual_count = 0;
    while let Some(next) = rig.network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::BlobsByRange(blob),
            inbound_request_id: _,
        } = next
        {
            if blob.is_some() {
                actual_count += 1;
            } else {
                break;
            }
        } else {
            panic!("unexpected message {:?}", next);
        }
    }
    if test_spec::<E>().fulu_fork_epoch.is_some() {
        assert_eq!(0, actual_count, "Post-Fulu should return 0 blobs");
    } else {
        assert_eq!(blob_count, actual_count);
    }
}

#[tokio::test]
async fn test_blobs_by_range_spans_fulu_fork() {
    // Only test for Electra & Fulu fork transition
    if test_spec::<E>().electra_fork_epoch.is_none() {
        return;
    };
    let mut spec = test_spec::<E>();
    spec.fulu_fork_epoch = Some(Epoch::new(1));
    spec.gloas_fork_epoch = Some(Epoch::new(2));

    let mut rig = TestRig::new_parametric(
        64,
        BeaconProcessorConfig::default(),
        NodeCustodyType::Fullnode,
        spec,
    )
    .await;

    let start_slot = 16;
    // This will span from epoch 0 (Electra) to epoch 1 (Fulu)
    let slot_count = 32;

    rig.enqueue_blobs_by_range_request(start_slot, slot_count);

    let mut blob_count = 0;
    for slot in start_slot..slot_count {
        let root = rig
            .chain
            .block_root_at_slot(Slot::new(slot), WhenSlotSkipped::None)
            .unwrap();
        blob_count += root
            .map(|root| {
                rig.chain
                    .get_blobs(&root)
                    .map(|list| list.len())
                    .unwrap_or(0)
            })
            .unwrap_or(0);
    }

    let mut actual_count = 0;

    while let Some(next) = rig.network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::BlobsByRange(blob),
            inbound_request_id: _,
        } = next
        {
            if blob.is_some() {
                actual_count += 1;
            } else {
                break;
            }
        } else {
            panic!("unexpected message {:?}", next);
        }
    }
    assert_eq!(blob_count, actual_count);
}

#[tokio::test]
async fn test_blobs_by_root() {
    if test_spec::<E>().deneb_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new(64).await;

    // Get the block root of a sample slot, e.g., slot 1
    let block_root = rig
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();

    let blobs = rig.chain.get_blobs(&block_root).unwrap();
    let blob_count = blobs.len();

    let blob_ids: Vec<BlobIdentifier> = (0..blob_count)
        .map(|index| BlobIdentifier {
            block_root,
            index: index as u64,
        })
        .collect();

    let blob_ids_list = RuntimeVariableList::new(blob_ids, blob_count).unwrap();

    rig.enqueue_blobs_by_root_request(blob_ids_list);

    let mut blob_count = 0;
    let root = rig
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap();
    blob_count += root
        .map(|root| {
            rig.chain
                .get_blobs(&root)
                .map(|list| list.len())
                .unwrap_or(0)
        })
        .unwrap_or(0);

    let mut actual_count = 0;

    while let Some(next) = rig.network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::BlobsByRoot(blob),
            inbound_request_id: _,
        } = next
        {
            if blob.is_some() {
                actual_count += 1;
            } else {
                break;
            }
        } else {
            panic!("unexpected message {:?}", next);
        }
    }
    assert_eq!(blob_count, actual_count);
}

#[tokio::test]
async fn test_blobs_by_root_post_fulu_should_return_empty() {
    // Only test for Fulu fork
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new(64).await;

    let block_root = rig
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();

    let blob_ids = vec![BlobIdentifier {
        block_root,
        index: 0,
    }];

    let blob_ids_list = RuntimeVariableList::new(blob_ids, 1).unwrap();

    rig.enqueue_blobs_by_root_request(blob_ids_list);

    let mut actual_count = 0;

    while let Some(next) = rig.network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::BlobsByRoot(blob),
            inbound_request_id: _,
        } = next
        {
            if blob.is_some() {
                actual_count += 1;
            } else {
                break;
            }
        } else {
            panic!("unexpected message {:?}", next);
        }
    }
    // Post-Fulu should return 0 blobs
    assert_eq!(0, actual_count);
}

/// Ensure that data column processing that results in block import sends a sync notification
#[tokio::test]
async fn test_data_column_import_notifies_sync() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    }

    let mut rig = TestRig::new(SMALL_CHAIN).await;
    let block_root = rig.next_block.canonical_root();

    // Enqueue the block first to prepare for data column processing
    rig.enqueue_gossip_block();
    rig.assert_event_journal_completes(&[WorkType::GossipBlock])
        .await;
    rig.receive_sync_messages_with_timeout(Duration::from_millis(100), Some(1))
        .await
        .expect("should receive sync message");

    // Enqueue data columns which should trigger block import when complete
    let num_data_columns = rig.next_data_columns.as_ref().map(|c| c.len()).unwrap_or(0);
    if num_data_columns > 0 {
        for i in 0..num_data_columns {
            rig.enqueue_gossip_data_columns(i);
            rig.assert_event_journal_completes(&[WorkType::GossipDataColumnSidecar])
                .await;
        }

        // Verify block import succeeded
        assert_eq!(
            rig.head_root(),
            block_root,
            "block should be imported and become head"
        );

        // Check that sync was notified of the successful import
        let sync_messages = rig
            .receive_sync_messages_with_timeout(Duration::from_millis(100), Some(1))
            .await
            .expect("should receive sync message");

        // Verify we received the expected GossipBlockProcessResult message
        assert_eq!(
            sync_messages.len(),
            1,
            "should receive exactly one sync message"
        );
        match &sync_messages[0] {
            SyncMessage::GossipBlockProcessResult {
                block_root: msg_block_root,
                imported,
            } => {
                assert_eq!(*msg_block_root, block_root, "block root should match");
                assert!(*imported, "block should be marked as imported");
            }
            other => panic!("expected GossipBlockProcessResult, got {:?}", other),
        }
    }
}

#[tokio::test]
async fn test_data_columns_by_range_request_only_returns_requested_columns() {
    if test_spec::<E>().fulu_fork_epoch.is_none() {
        return;
    };

    let mut rig = TestRig::new(64).await;
    let slot_count = 4;

    let all_custody_columns = rig
        .chain
        .sampling_columns_for_epoch(rig.chain.epoch().unwrap());
    let available_columns: Vec<u64> = all_custody_columns.to_vec();

    let requested_columns = vec![available_columns[0], available_columns[2]];

    rig.enqueue_data_columns_by_range_request(slot_count, requested_columns.clone());

    let mut received_columns = Vec::new();

    while let Some(next) = rig.network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::DataColumnsByRange(data_column),
            inbound_request_id: _,
        } = next
        {
            if let Some(column) = data_column {
                received_columns.push(column.index);
            } else {
                break;
            }
        } else {
            panic!("unexpected message {:?}", next);
        }
    }

    for received_index in &received_columns {
        assert!(
            requested_columns.contains(received_index),
            "Received column index {} was not in requested columns {:?}",
            received_index,
            requested_columns
        );
    }

    let unique_received: HashSet<_> = received_columns.into_iter().collect();
    assert!(
        !unique_received.is_empty(),
        "Should have received at least some data columns"
    );
}
