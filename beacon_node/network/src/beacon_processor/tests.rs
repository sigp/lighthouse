#![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::beacon_processor::work_reprocessing_queue::QUEUED_ATTESTATION_DELAY;
use crate::beacon_processor::*;
use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::{BeaconChain, MAXIMUM_GOSSIP_CLOCK_DISPARITY};
use environment::{null_logger, Environment, EnvironmentBuilder};
use eth2_libp2p::{
    discv5::enr::{CombinedKey, EnrBuilder},
    rpc::methods::{MetaData, MetaDataV2},
    types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield},
    MessageId, NetworkGlobals, PeerId,
};
use slot_clock::SlotClock;
use std::cmp;
use std::iter::Iterator;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, EthSpec, MainnetEthSpec, ProposerSlashing, SignedBeaconBlock,
    SignedVoluntaryExit, SubnetId,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const SMALL_CHAIN: u64 = 2;
const LONG_CHAIN: u64 = SLOTS_PER_EPOCH * 2;

const TCP_PORT: u16 = 42;
const UDP_PORT: u16 = 42;
const SEQ_NUMBER: u64 = 0;

/// The default time to wait for `BeaconProcessor` events.
const STANDARD_TIMEOUT: Duration = Duration::from_secs(10);

/// Provides utilities for testing the `BeaconProcessor`.
struct TestRig {
    chain: Arc<BeaconChain<T>>,
    next_block: SignedBeaconBlock<E>,
    attestations: Vec<(Attestation<E>, SubnetId)>,
    next_block_attestations: Vec<(Attestation<E>, SubnetId)>,
    next_block_aggregate_attestations: Vec<SignedAggregateAndProof<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    beacon_processor_tx: mpsc::Sender<WorkEvent<T>>,
    work_journal_rx: mpsc::Receiver<&'static str>,
    _network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
    environment: Option<Environment<E>>,
}

/// This custom drop implementation ensures that we shut down the tokio runtime gracefully. Without
/// it, tests will hang indefinitely.
impl Drop for TestRig {
    fn drop(&mut self) {
        // Causes the beacon processor to shutdown.
        self.beacon_processor_tx = mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN).0;
        self.environment.take().unwrap().shutdown_on_idle();
    }
}

impl TestRig {
    pub fn new(chain_length: u64) -> Self {
        // This allows for testing voluntary exits without building out a massive chain.
        let mut spec = E::default_spec();
        spec.shard_committee_period = 2;

        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec)
            .deterministic_keypairs(VALIDATOR_COUNT)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        for _ in 0..chain_length {
            harness.extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            );

            harness.advance_slot();
        }

        let head = harness.chain.head().unwrap();

        assert_eq!(
            harness.chain.slot().unwrap(),
            head.beacon_block.slot() + 1,
            "precondition: current slot is one after head"
        );

        let (next_block, next_state) =
            harness.make_block(head.beacon_state.clone(), harness.chain.slot().unwrap());

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
                next_block.state_root(),
                next_block.canonical_root(),
                next_block.slot(),
            )
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let next_block_aggregate_attestations = harness
            .make_attestations(
                &harness.get_all_validators(),
                &next_state,
                next_block.state_root(),
                next_block.canonical_root().into(),
                next_block.slot(),
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

        let chain = harness.chain;

        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let log = null_logger().unwrap();

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);
        let (sync_tx, _sync_rx) = mpsc::unbounded_channel();

        // Default metadata
        let meta_data = MetaData::V2(MetaDataV2 {
            seq_number: SEQ_NUMBER,
            attnets: EnrAttestationBitfield::<MainnetEthSpec>::default(),
            syncnets: EnrSyncCommitteeBitfield::<MainnetEthSpec>::default(),
        });
        let enr_key = CombinedKey::generate_secp256k1();
        let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
        let network_globals = Arc::new(NetworkGlobals::new(
            enr,
            TCP_PORT,
            UDP_PORT,
            meta_data,
            vec![],
            &log,
        ));

        let mut environment = EnvironmentBuilder::mainnet()
            .null_logger()
            .unwrap()
            .multi_threaded_tokio_runtime()
            .unwrap()
            .build()
            .unwrap();

        let executor = environment.core_context().executor;

        let (work_journal_tx, work_journal_rx) = mpsc::channel(16_364);

        BeaconProcessor {
            beacon_chain: Arc::downgrade(&chain),
            network_tx,
            sync_tx,
            network_globals,
            executor,
            max_workers: cmp::max(1, num_cpus::get()),
            current_workers: 0,
            log: log.clone(),
        }
        .spawn_manager(beacon_processor_rx, Some(work_journal_tx));

        Self {
            chain,
            next_block,
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
            environment: Some(environment),
        }
    }

    pub fn head_root(&self) -> Hash256 {
        self.chain.head().unwrap().beacon_block_root
    }

    pub fn enqueue_gossip_block(&self) {
        self.beacon_processor_tx
            .try_send(WorkEvent::gossip_beacon_block(
                junk_message_id(),
                junk_peer_id(),
                Client::default(),
                Box::new(self.next_block.clone()),
                Duration::from_secs(0),
            ))
            .unwrap();
    }

    pub fn enqueue_rpc_block(&self) {
        let (event, _rx) = WorkEvent::rpc_beacon_block(Box::new(self.next_block.clone()));
        self.beacon_processor_tx.try_send(event).unwrap();
    }

    pub fn enqueue_unaggregated_attestation(&self) {
        let (attestation, subnet_id) = self.attestations.first().unwrap().clone();
        self.beacon_processor_tx
            .try_send(WorkEvent::unaggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                attestation,
                subnet_id,
                true,
                Duration::from_secs(0),
            ))
            .unwrap();
    }

    pub fn enqueue_gossip_attester_slashing(&self) {
        self.beacon_processor_tx
            .try_send(WorkEvent::gossip_attester_slashing(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.attester_slashing.clone()),
            ))
            .unwrap();
    }

    pub fn enqueue_gossip_proposer_slashing(&self) {
        self.beacon_processor_tx
            .try_send(WorkEvent::gossip_proposer_slashing(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.proposer_slashing.clone()),
            ))
            .unwrap();
    }

    pub fn enqueue_gossip_voluntary_exit(&self) {
        self.beacon_processor_tx
            .try_send(WorkEvent::gossip_voluntary_exit(
                junk_message_id(),
                junk_peer_id(),
                Box::new(self.voluntary_exit.clone()),
            ))
            .unwrap();
    }

    pub fn enqueue_next_block_unaggregated_attestation(&self) {
        let (attestation, subnet_id) = self.next_block_attestations.first().unwrap().clone();
        self.beacon_processor_tx
            .try_send(WorkEvent::unaggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                attestation,
                subnet_id,
                true,
                Duration::from_secs(0),
            ))
            .unwrap();
    }

    pub fn enqueue_next_block_aggregated_attestation(&self) {
        let aggregate = self
            .next_block_aggregate_attestations
            .first()
            .unwrap()
            .clone();
        self.beacon_processor_tx
            .try_send(WorkEvent::aggregated_attestation(
                junk_message_id(),
                junk_peer_id(),
                aggregate,
                Duration::from_secs(0),
            ))
            .unwrap();
    }

    fn runtime(&mut self) -> Arc<Runtime> {
        self.environment
            .as_mut()
            .unwrap()
            .core_context()
            .executor
            .runtime()
            .upgrade()
            .unwrap()
    }

    /// Assert that the `BeaconProcessor` doesn't produce any events in the given `duration`.
    pub fn assert_no_events_for(&mut self, duration: Duration) {
        self.runtime().block_on(async {
            tokio::select! {
                _ = tokio::time::sleep(duration) => (),
                event = self.work_journal_rx.recv() => panic!(
                    "received {:?} within {:?} when expecting no events",
                    event,
                    duration
                ),
            }
        })
    }

    /// Checks that the `BeaconProcessor` event journal contains the `expected` events in the given
    /// order with a matching number of `WORKER_FREED` events in between. `NOTHING_TO_DO` events
    /// are ignored.
    ///
    /// Given the described logic, `expected` must not contain `WORKER_FREED` or `NOTHING_TO_DO`
    /// events.
    pub fn assert_event_journal_contains_ordered(&mut self, expected: &[&str]) {
        assert!(expected
            .iter()
            .all(|ev| ev != &WORKER_FREED && ev != &NOTHING_TO_DO));

        let (events, worker_freed_remaining) = self.runtime().block_on(async {
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

            (events, worker_freed_remaining)
        });

        assert_eq!(events, expected);
        assert_eq!(worker_freed_remaining, 0);
    }

    pub fn assert_event_journal(&mut self, expected: &[&str]) {
        self.assert_event_journal_with_timeout(expected, STANDARD_TIMEOUT);
    }

    /// Assert that the `BeaconProcessor` event journal is as `expected`.
    ///
    /// ## Note
    ///
    /// We won't attempt to listen for any more than `expected.len()` events. As such, it makes sense
    /// to use the `NOTHING_TO_DO` event to ensure that execution has completed.
    pub fn assert_event_journal_with_timeout(&mut self, expected: &[&str], timeout: Duration) {
        let events = self.runtime().block_on(async {
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

            events
        });

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
#[test]
fn import_gossip_block_acceptably_early() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - MAXIMUM_GOSSIP_CLOCK_DISPARITY);

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

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

    rig.assert_event_journal(&[DELAYED_IMPORT_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}

/// Blocks that are *too* early shouldn't get into the delay queue.
#[test]
fn import_gossip_block_unacceptably_early() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    let slot_start = rig
        .chain
        .slot_clock
        .start_of(rig.next_block.slot())
        .unwrap();

    rig.chain
        .slot_clock
        .set_current_time(slot_start - MAXIMUM_GOSSIP_CLOCK_DISPARITY - Duration::from_millis(1));

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot() - 1,
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    // Waiting for 5 seconds is a bit arbitrary, however it *should* be long enough to ensure the
    // block isn't imported.
    rig.assert_no_events_for(Duration::from_secs(5));

    assert!(
        rig.head_root() != rig.next_block.canonical_root(),
        "block should not be imported"
    );
}

/// Blocks that arrive on-time should be processed normally.
#[test]
fn import_gossip_block_at_current_slot() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot(),
        "chain should be at the correct slot"
    );

    rig.enqueue_gossip_block();

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.head_root(),
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}

/// Ensure a valid attestation can be imported.
#[test]
fn import_gossip_attestation() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_unaggregated_attestation();

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO]);

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
fn attestation_to_unknown_block_processed(import_method: BlockImportMethod) {
    let mut rig = TestRig::new(SMALL_CHAIN);

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_next_block_unaggregated_attestation();

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.

    let block_event = match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            GOSSIP_BLOCK
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            RPC_BLOCK
        }
    };

    rig.assert_event_journal_contains_ordered(&[block_event, UNKNOWN_BLOCK_ATTESTATION]);

    // Run fork choice, since it isn't run when processing an RPC block. At runtime it is the
    // responsibility of the sync manager to do this.
    rig.chain.fork_choice().unwrap();

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

#[test]
fn attestation_to_unknown_block_processed_after_gossip_block() {
    attestation_to_unknown_block_processed(BlockImportMethod::Gossip)
}

#[test]
fn attestation_to_unknown_block_processed_after_rpc_block() {
    attestation_to_unknown_block_processed(BlockImportMethod::Rpc)
}

/// Ensure that attestations that reference an unknown block get properly re-queued and
/// re-processed upon importing the block.
fn aggregate_attestation_to_unknown_block(import_method: BlockImportMethod) {
    let mut rig = TestRig::new(SMALL_CHAIN);

    // Empty the op pool.
    rig.chain
        .op_pool
        .prune_attestations(u64::max_value().into());
    assert_eq!(rig.chain.op_pool.num_attestations(), 0);

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.op_pool.num_attestations();

    rig.enqueue_next_block_aggregated_attestation();

    rig.assert_event_journal(&[GOSSIP_AGGREGATE, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Send the block and ensure that the attestation is received back and imported.

    let block_event = match import_method {
        BlockImportMethod::Gossip => {
            rig.enqueue_gossip_block();
            GOSSIP_BLOCK
        }
        BlockImportMethod::Rpc => {
            rig.enqueue_rpc_block();
            RPC_BLOCK
        }
    };

    rig.assert_event_journal_contains_ordered(&[block_event, UNKNOWN_BLOCK_AGGREGATE]);

    // Run fork choice, since it isn't run when processing an RPC block. At runtime it is the
    // responsibility of the sync manager to do this.
    rig.chain.fork_choice().unwrap();

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

#[test]
fn aggregate_attestation_to_unknown_block_processed_after_gossip_block() {
    aggregate_attestation_to_unknown_block(BlockImportMethod::Gossip)
}

#[test]
fn aggregate_attestation_to_unknown_block_processed_after_rpc_block() {
    aggregate_attestation_to_unknown_block(BlockImportMethod::Rpc)
}

/// Ensure that attestations that reference an unknown block get properly re-queued and re-processed
/// when the block is not seen.
#[test]
fn requeue_unknown_block_gossip_attestation_without_import() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.naive_aggregation_pool.read().num_items();

    rig.enqueue_next_block_unaggregated_attestation();

    rig.assert_event_journal(&[GOSSIP_ATTESTATION, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[UNKNOWN_BLOCK_ATTESTATION, WORKER_FREED, NOTHING_TO_DO],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
    );

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );
}

/// Ensure that aggregate that reference an unknown block get properly re-queued and re-processed
/// when the block is not seen.
#[test]
fn requeue_unknown_block_gossip_aggregated_attestation_without_import() {
    let mut rig = TestRig::new(SMALL_CHAIN);

    // Send the attestation but not the block, and check that it was not imported.

    let initial_attns = rig.chain.op_pool.num_attestations();

    rig.enqueue_next_block_aggregated_attestation();

    rig.assert_event_journal(&[GOSSIP_AGGREGATE, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.naive_aggregation_pool.read().num_items(),
        initial_attns,
        "Attestation should not have been included."
    );

    // Ensure that the attestation is received back but not imported.

    rig.assert_event_journal_with_timeout(
        &[UNKNOWN_BLOCK_AGGREGATE, WORKER_FREED, NOTHING_TO_DO],
        Duration::from_secs(1) + QUEUED_ATTESTATION_DELAY,
    );

    assert_eq!(
        rig.chain.op_pool.num_attestations(),
        initial_attns,
        "Attestation should not have been included."
    );
}

/// Ensure a bunch of valid operations can be imported.
#[test]
fn import_misc_gossip_ops() {
    // Exits need the long chain so validators aren't too young to exit.
    let mut rig = TestRig::new(LONG_CHAIN);

    /*
     * Attester slashing
     */

    let initial_attester_slashings = rig.chain.op_pool.num_attester_slashings();

    rig.enqueue_gossip_attester_slashing();

    rig.assert_event_journal(&[GOSSIP_ATTESTER_SLASHING, WORKER_FREED, NOTHING_TO_DO]);

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

    rig.assert_event_journal(&[GOSSIP_PROPOSER_SLASHING, WORKER_FREED, NOTHING_TO_DO]);

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

    rig.assert_event_journal(&[GOSSIP_VOLUNTARY_EXIT, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.op_pool.num_voluntary_exits(),
        initial_voluntary_exits + 1,
        "op pool should have one more exit"
    );
}
