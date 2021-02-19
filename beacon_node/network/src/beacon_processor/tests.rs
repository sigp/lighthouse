// #![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::beacon_processor::{
    BeaconProcessor, WorkEvent as BeaconWorkEvent, WorkEvent, MAX_WORK_EVENT_QUEUE_LEN,
};
use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain, StateSkipConfig,
};
use environment::null_logger;
use eth2_libp2p::{
    rpc::methods::MetaData,
    types::{EnrBitfield, SyncState},
    Enr, EnrExt, NetworkGlobals, PeerId,
};
use futures::stream::{Stream, StreamExt};
use futures::FutureExt;
use state_processing::per_slot_processing;
use std::convert::TryInto;
use std::iter::Iterator;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::Duration;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypairs, AggregateSignature, Attestation, AttesterSlashing,
    BeaconState, BitList, Domain, EthSpec, Hash256, Keypair, MainnetEthSpec, ProposerSlashing,
    RelativeEpoch, SelectionProof, SignedBeaconBlock, SignedRoot, SignedVoluntaryExit, Slot,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const CHAIN_LENGTH: u64 = SLOTS_PER_EPOCH * 5 - 1; // Make `next_block` an epoch transition
const JUSTIFIED_EPOCH: u64 = 4;
const FINALIZED_EPOCH: u64 = 3;
const TCP_PORT: u16 = 42;
const UDP_PORT: u16 = 42;
const SEQ_NUMBER: u64 = 0;
const EXTERNAL_ADDR: &str = "/ip4/0.0.0.0/tcp/9000";

/// Skipping the slots around the epoch boundary allows us to check that we're obtaining states
/// from skipped slots for the finalized and justified checkpoints (instead of the state from the
/// block that those roots point to).
const SKIPPED_SLOTS: &[u64] = &[
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH - 1,
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH - 1,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH,
];

struct ApiTester {
    chain: Arc<BeaconChain<T>>,
    next_block: SignedBeaconBlock<E>,
    attestations: Vec<Attestation<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    validator_keypairs: Vec<Keypair>,
    beacon_processor_tx: mpsc::Sender<WorkEvent<T>>,
}

impl ApiTester {
    pub fn new() -> Self {
        let mut harness = BeaconChainHarness::new(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
        );

        harness.advance_slot();

        for _ in 0..CHAIN_LENGTH {
            let slot = harness.chain.slot().unwrap().as_u64();

            if !SKIPPED_SLOTS.contains(&slot) {
                harness.extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                );
            }

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

        assert_eq!(
            chain.head_info().unwrap().finalized_checkpoint.epoch,
            2,
            "precondition: finality"
        );
        assert_eq!(
            chain
                .head_info()
                .unwrap()
                .current_justified_checkpoint
                .epoch,
            3,
            "precondition: justification"
        );

        let (network_tx, network_rx) = mpsc::unbounded_channel();

        let log = null_logger().unwrap();

        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let (sync_tx, sync_rx) = mpsc::unbounded_channel();

        let network_globals = NetworkGlobals::new(enr, TCP_PORT, UDP_PORT, meta_data, vec![], &log);

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
        .spawn_manager(beacon_processor_receive);

        Self {
            chain,
            next_block,
            attestations,
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            validator_keypairs: harness.validator_keypairs,
            beacon_processor_tx,
        }
    }
}
