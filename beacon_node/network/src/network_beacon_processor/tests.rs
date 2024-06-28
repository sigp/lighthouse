#![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::{
    network_beacon_processor::{
        ChainSegmentProcessId, DuplicateCache, InvalidBlockStorage, NetworkBeaconProcessor,
    },
    service::NetworkMessage,
    sync::{manager::BlockProcessType, SyncMessage},
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::test_utils::{
    test_spec, AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::{BeaconChain, WhenSlotSkipped};
use beacon_processor::{work_reprocessing_queue::*, *};
use lighthouse_network::discovery::ConnectionId;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::SubstreamId;
use lighthouse_network::{
    discv5::enr::{self, CombinedKey},
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield},
    Client, MessageId, NetworkGlobals, PeerId, Response,
};
use slot_clock::SlotClock;
use std::iter::Iterator;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{
    Attestation, AttesterSlashing, BlobSidecar, BlobSidecarList, Epoch, Hash256, MainnetEthSpec,
    ProposerSlashing, SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit, Slot,
    SubnetId,
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
    attestations: Vec<(Attestation<E>, SubnetId)>,
    next_block_attestations: Vec<(Attestation<E>, SubnetId)>,
    next_block_aggregate_attestations: Vec<SignedAggregateAndProof<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    beacon_processor_tx: BeaconProcessorSend<E>,
    work_journal_rx: mpsc::Receiver<&'static str>,
    _network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
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
        Self::new_parametric(
            chain_length,
            BeaconProcessorConfig::default().enable_backfill_rate_limiting,
        )
        .await
    }

    pub async fn new_parametric(chain_length: u64, enable_backfill_rate_limiting: bool) -> Self {
        // This allows for testing voluntary exits without building out a massive chain.
        let mut spec = test_spec::<E>();
        spec.shard_committee_period = 2;

        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec)
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .mock_execution_layer()
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

        let (next_block_tuple, next_state) = harness
            .make_block(head.beacon_state.clone(), harness.chain.slot().unwrap())
            .await;

        let head_state_root = head.beacon_state_root();
        let attestations = harness
            .get_unaggregated_attestations(
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
            .get_unaggregated_attestations(
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

        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let log = harness.logger().clone();

        let beacon_processor_config = BeaconProcessorConfig {
            enable_backfill_rate_limiting,
            ..Default::default()
        };
        let BeaconProcessorChannels {
            beacon_processor_tx,
            beacon_processor_rx,
            work_reprocessing_tx,
            work_reprocessing_rx,
        } = BeaconProcessorChannels::new(&beacon_processor_config);

        let (sync_tx, _sync_rx) = mpsc::unbounded_channel();

        // Default metadata
        let meta_data = MetaData::V2(MetaDataV2 {
            seq_number: SEQ_NUMBER,
            attnets: EnrAttestationBitfield::<MainnetEthSpec>::default(),
            syncnets: EnrSyncCommitteeBitfield::<MainnetEthSpec>::default(),
        });
        let enr_key = CombinedKey::generate_secp256k1();
        let enr = enr::Enr::builder().build(&enr_key).unwrap();
        let network_globals = Arc::new(NetworkGlobals::new(enr, meta_data, vec![], false, &log));

        let executor = harness.runtime.task_executor.clone();

        let (work_journal_tx, work_journal_rx) = mpsc::channel(16_364);

        let duplicate_cache = DuplicateCache::default();
        let network_beacon_processor = NetworkBeaconProcessor {
            beacon_processor_send: beacon_processor_tx.clone(),
            duplicate_cache: duplicate_cache.clone(),
            chain: harness.chain.clone(),
            network_tx,
            sync_tx,
            reprocess_tx: work_reprocessing_tx.clone(),
            network_globals: network_globals.clone(),
            invalid_block_storage: InvalidBlockStorage::Disabled,
            executor: executor.clone(),
            log: log.clone(),
        };
        let network_beacon_processor = Arc::new(network_beacon_processor);

        let beacon_processor = BeaconProcessor {
            network_globals,
            executor,
            current_workers: 0,
            config: beacon_processor_config,
            log: log.clone(),
        }
        .spawn_manager(
            beacon_processor_rx,
            work_reprocessing_tx,
            work_reprocessing_rx,
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
        let blob_sidecars = if let Some((kzg_proofs, blobs)) = next_block_tuple.1 {
            Some(BlobSidecar::build_sidecars(blobs, &block, kzg_proofs).unwrap())
        } else {
            None
        };
        Self {
            chain,
            next_block: block,
            next_blobs: blob_sidecars,
            attestations,
            next_block_attestations,
            next_block_aggregate_attestations,
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            beacon_processor_tx,
            work_journal_rx,
            _network_rx,
            _sync_rx,
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
            let blobs = FixedBlobSidecarList::from(blobs.into_iter().map(Some).collect::<Vec<_>>());
            self.network_beacon_processor
                .send_rpc_blobs(
                    self.next_block.canonical_root(),
                    blobs,
                    std::time::Duration::default(),
                    BlockProcessType::SingleBlock { id: 1 },
                )
                .unwrap();
        }
    }

    pub fn enqueue_blobs_by_range_request(&self, count: u64) {
        self.network_beacon_processor
            .send_blobs_by_range_request(
                PeerId::random(),
                (ConnectionId::new_unchecked(42), SubstreamId::new(24)),
                BlobsByRangeRequest {
                    start_slot: 0,
                    count,
                },
            )
            .unwrap();
    }

    pub fn enqueue_backfill_batch(&self) {
        self.network_beacon_processor
            .send_chain_segment(
                ChainSegmentProcessId::BackSyncBatchId(Epoch::default()),
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
    pub async fn assert_event_journal_contains_ordered(&mut self, expected: &[&str]) {
        assert!(expected
            .iter()
            .all(|ev| ev != &WORKER_FREED && ev != &NOTHING_TO_DO));

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
        self.assert_event_journal_with_timeout(expected, STANDARD_TIMEOUT)
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
}

fn junk_peer_id() -> PeerId {
    PeerId::random()
}

fn junk_message_id() -> MessageId {
    MessageId::new(&[])
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

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO])
        .await;

    let num_blobs = rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0);
    for i in 0..num_blobs {
        rig.enqueue_gossip_blob(i);
        rig.assert_event_journal(&[GOSSIP_BLOBS_SIDECAR, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[DELAYED_IMPORT_BLOCK, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO])
        .await;

    // Waiting for 5 seconds is a bit arbitrary, however it *should* be long enough to ensure the
    // block isn't imported.
    rig.assert_no_events_for(Duration::from_secs(5)).await;

    assert!(
        rig.head_root() != rig.next_block.canonical_root(),
        "block should not be imported"
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

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO])
        .await;

    let num_blobs = rig
        .next_blobs
        .as_ref()
        .map(|blobs| blobs.len())
        .unwrap_or(0);

    for i in 0..num_blobs {
        rig.enqueue_gossip_blob(i);

        rig.assert_event_journal(&[GOSSIP_BLOBS_SIDECAR, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.
    let num_blobs = rig
        .next_blobs
        .as_ref()
        .map(|blobs| blobs.len())
        .unwrap_or(0);
    let mut events = vec![];
    match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            events.push(GOSSIP_BLOCK);
            for i in 0..num_blobs {
                rig.enqueue_gossip_blob(i);
                events.push(GOSSIP_BLOBS_SIDECAR);
            }
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            events.push(RPC_BLOCK);
            if num_blobs > 0 {
                rig.enqueue_single_lookup_rpc_blobs();
                events.push(RPC_BLOBS);
            }
        }
    };

    events.push(UNKNOWN_BLOCK_ATTESTATION);

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

    rig.assert_event_journal(&[GOSSIP_AGGREGATE, WORKER_FREED, NOTHING_TO_DO])
        .await;

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.
    let num_blobs = rig
        .next_blobs
        .as_ref()
        .map(|blobs| blobs.len())
        .unwrap_or(0);
    let mut events = vec![];
    match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            events.push(GOSSIP_BLOCK);
            for i in 0..num_blobs {
                rig.enqueue_gossip_blob(i);
                events.push(GOSSIP_BLOBS_SIDECAR);
            }
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            events.push(RPC_BLOCK);
            if num_blobs > 0 {
                rig.enqueue_single_lookup_rpc_blobs();
                events.push(RPC_BLOBS);
            }
        }
    };

    events.push(UNKNOWN_BLOCK_AGGREGATE);

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

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[UNKNOWN_BLOCK_ATTESTATION, WORKER_FREED, NOTHING_TO_DO],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
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

    rig.assert_event_journal(&[GOSSIP_AGGREGATE, WORKER_FREED, NOTHING_TO_DO])
        .await;

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[UNKNOWN_BLOCK_AGGREGATE, WORKER_FREED, NOTHING_TO_DO],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
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

    rig.assert_event_journal(&[GOSSIP_ATTESTER_SLASHING, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[GOSSIP_PROPOSER_SLASHING, WORKER_FREED, NOTHING_TO_DO])
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

    rig.assert_event_journal(&[GOSSIP_VOLUNTARY_EXIT, WORKER_FREED, NOTHING_TO_DO])
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
    rig.assert_event_journal(&[RPC_BLOCK, WORKER_FREED, NOTHING_TO_DO])
        .await;

    rig.enqueue_single_lookup_rpc_blobs();
    if rig.next_blobs.as_ref().map(|b| b.len()).unwrap_or(0) > 0 {
        rig.assert_event_journal(&[RPC_BLOBS, WORKER_FREED, NOTHING_TO_DO])
            .await;
    }

    // next_block shouldn't be processed since it couldn't get the
    // duplicate cache handle
    assert_ne!(next_block_root, rig.head_root());

    drop(handle);

    // The block should arrive at the beacon processor again after
    // the specified delay.
    tokio::time::sleep(QUEUED_RPC_BLOCK_DELAY).await;

    rig.assert_event_journal(&[RPC_BLOCK]).await;
    // Add an extra delay for block processing
    tokio::time::sleep(Duration::from_millis(10)).await;
    // head should update to next block now since the duplicate
    // cache handle was dropped.
    assert_eq!(next_block_root, rig.head_root());
}

/// Ensure that backfill batches get rate-limited and processing is scheduled at specified intervals.
#[tokio::test]
async fn test_backfill_sync_processing() {
    let mut rig = TestRig::new(SMALL_CHAIN).await;
    // Note: to verify the exact event times in an integration test is not straight forward here
    // (not straight forward to manipulate `TestingSlotClock` due to cloning of `SlotClock` in code)
    // and makes the test very slow, hence timing calculation is unit tested separately in
    // `work_reprocessing_queue`.
    for _ in 0..1 {
        rig.enqueue_backfill_batch();
        // ensure queued batch is not processed until later
        rig.assert_no_events_for(Duration::from_millis(100)).await;
        // A new batch should be processed within a slot.
        rig.assert_event_journal_with_timeout(
            &[CHAIN_SEGMENT_BACKFILL, WORKER_FREED, NOTHING_TO_DO],
            rig.chain.slot_clock.slot_duration(),
        )
        .await;
    }
}

/// Ensure that backfill batches get processed as fast as they can when rate-limiting is disabled.
#[tokio::test]
async fn test_backfill_sync_processing_rate_limiting_disabled() {
    let enable_backfill_rate_limiting = false;
    let mut rig = TestRig::new_parametric(SMALL_CHAIN, enable_backfill_rate_limiting).await;

    for _ in 0..3 {
        rig.enqueue_backfill_batch();
    }

    // ensure all batches are processed
    rig.assert_event_journal_with_timeout(
        &[
            CHAIN_SEGMENT_BACKFILL,
            CHAIN_SEGMENT_BACKFILL,
            CHAIN_SEGMENT_BACKFILL,
        ],
        Duration::from_millis(100),
    )
    .await;
}

#[tokio::test]
async fn test_blobs_by_range() {
    if test_spec::<E>().deneb_fork_epoch.is_none() {
        return;
    };
    let mut rig = TestRig::new(64).await;
    let slot_count = 32;
    rig.enqueue_blobs_by_range_request(slot_count);

    let mut blob_count = 0;
    for slot in 0..slot_count {
        let root = rig
            .chain
            .block_root_at_slot(Slot::new(slot), WhenSlotSkipped::None)
            .unwrap();
        blob_count += root
            .map(|root| rig.chain.get_blobs(&root).unwrap_or_default().len())
            .unwrap_or(0);
    }
    let mut actual_count = 0;
    while let Some(next) = rig._network_rx.recv().await {
        if let NetworkMessage::SendResponse {
            peer_id: _,
            response: Response::BlobsByRange(blob),
            id: _,
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
