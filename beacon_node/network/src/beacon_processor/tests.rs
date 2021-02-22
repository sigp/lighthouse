// #![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::beacon_processor::*;
use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};
use discv5::enr::{CombinedKey, EnrBuilder};
use environment::{null_logger, Environment, EnvironmentBuilder};
use eth2_libp2p::{rpc::methods::MetaData, types::EnrBitfield, MessageId, NetworkGlobals, PeerId};
use slot_clock::SlotClock;
use std::cmp;
use std::iter::Iterator;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::{
    test_utils::generate_deterministic_keypairs, Attestation, AttesterSlashing, Keypair,
    MainnetEthSpec, ProposerSlashing, SignedBeaconBlock, SignedVoluntaryExit,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const CHAIN_LENGTH: u64 = 2; // Make `next_block` an epoch transition
const TCP_PORT: u16 = 42;
const UDP_PORT: u16 = 42;
const SEQ_NUMBER: u64 = 0;

const STANDARD_TIMEOUT: Duration = Duration::from_secs(10);

struct TestRig {
    chain: Arc<BeaconChain<T>>,
    next_block: SignedBeaconBlock<E>,
    attestations: Vec<Attestation<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    validator_keypairs: Vec<Keypair>,
    beacon_processor_tx: mpsc::Sender<WorkEvent<T>>,
    work_journal_rx: mpsc::Receiver<String>,
    _network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
    environment: Option<Environment<E>>,
}

/// This custom drop implementation ensures that we shutdown the tokio runtime. Without it, tests
/// will hang indefinitely.
impl Drop for TestRig {
    fn drop(&mut self) {
        // Causes the beacon processor to shutdown.
        self.beacon_processor_tx = mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN).0;
        self.environment.take().unwrap().shutdown_on_idle();
    }
}

impl TestRig {
    pub fn new() -> Self {
        let mut harness = BeaconChainHarness::new(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
        );

        harness.advance_slot();

        for _ in 0..CHAIN_LENGTH {
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

        let (next_block, _next_state) =
            harness.make_block(head.beacon_state.clone(), harness.chain.slot().unwrap());

        let attestations = harness
            .get_unaggregated_attestations(
                &AttestationStrategy::AllValidators,
                &head.beacon_state,
                head.beacon_block_root,
                harness.chain.slot().unwrap(),
            )
            .into_iter()
            .map(|vec| vec.into_iter().map(|(attestation, _subnet_id)| attestation))
            .flatten()
            .collect::<Vec<_>>();

        assert!(
            !attestations.is_empty(),
            "precondition: attestations for testing"
        );

        let attester_slashing = harness.make_attester_slashing(vec![0, 1]);
        let proposer_slashing = harness.make_proposer_slashing(2);
        let voluntary_exit = harness.make_voluntary_exit(3, harness.chain.epoch().unwrap());

        // Changing this *after* the chain has been initialized is a bit cheeky, but it shouldn't
        // cause issue.
        //
        // This allows for testing voluntary exits without building out a massive chain.
        harness.chain.spec.shard_committee_period = 2;

        let chain = Arc::new(harness.chain);

        let (network_tx, _network_rx) = mpsc::unbounded_channel();

        let log = null_logger().unwrap();

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);
        let (sync_tx, _sync_rx) = mpsc::unbounded_channel();

        // Default metadata
        let meta_data = MetaData {
            seq_number: SEQ_NUMBER,
            attnets: EnrBitfield::<MainnetEthSpec>::default(),
        };
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
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            validator_keypairs: harness.validator_keypairs,
            beacon_processor_tx,
            work_journal_rx,
            _network_rx,
            _sync_rx,
            environment: Some(environment),
        }
    }

    pub fn enqueue_next_block(&self) {
        self.beacon_processor_tx
            .try_send(WorkEvent::gossip_beacon_block(
                MessageId::new(&[]),
                PeerId::random(),
                Box::new(self.next_block.clone()),
                Duration::from_secs(0),
            ))
            .unwrap();
    }

    pub fn assert_event_journal(&mut self, expected: &[&str]) {
        let events = self
            .environment
            .as_mut()
            .unwrap()
            .core_context()
            .executor
            .runtime()
            .upgrade()
            .unwrap()
            .block_on(async {
                let mut events = vec![];

                let drain_future = async {
                    loop {
                        match self.work_journal_rx.recv().await {
                            Some(event) => {
                                events.push(event);

                                // Break as soon as we collect the desired number of events.
                                //
                                // It's important to notice that we won't try and listen for any
                                // additional events, so it's important that you try and use the
                                // `NOTHING_TO_DO` event to ensure that you've reached the end of
                                // the stream.
                                if events.len() >= expected.len() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                };

                // Drain the expected number of events from the channel, or time out and give up.
                tokio::select! {
                    _ = tokio::time::sleep(STANDARD_TIMEOUT) => panic!(
                        "timeout ({:?}) expired waiting for events. expected {:?} but got {:?}",
                        STANDARD_TIMEOUT,
                        expected,
                        events
                    ),
                    _ = drain_future => {},
                }

                events
            });

        assert_eq!(
            events,
            expected
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn import_gossip_block_at_current_slot() {
    let mut rig = TestRig::new();

    assert_eq!(
        rig.chain.slot().unwrap(),
        rig.next_block.slot(),
        "chain should be at the correct slot"
    );

    rig.enqueue_next_block();

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.head().unwrap().beacon_block_root,
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}

#[test]
fn import_gossip_block_acceptably_early() {
    let mut rig = TestRig::new();

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

    rig.enqueue_next_block();

    rig.assert_event_journal(&[GOSSIP_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    rig.chain.slot_clock.set_slot(rig.next_block.slot().into());

    rig.assert_event_journal(&[DELAYED_IMPORT_BLOCK, WORKER_FREED, NOTHING_TO_DO]);

    assert_eq!(
        rig.chain.head().unwrap().beacon_block_root,
        rig.next_block.canonical_root(),
        "block should be imported and become head"
    );
}
