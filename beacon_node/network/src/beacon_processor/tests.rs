// #![cfg(not(debug_assertions))] // Tests are too slow in debug.
#![cfg(test)]

use crate::beacon_processor::{BeaconProcessor, WorkEvent, MAX_WORK_EVENT_QUEUE_LEN};
use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain,
};
use discv5::enr::{CombinedKey, EnrBuilder};
use environment::{null_logger, EnvironmentBuilder};
use eth2_libp2p::{rpc::methods::MetaData, types::EnrBitfield, NetworkGlobals};
use std::cmp;
use std::iter::Iterator;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{
    test_utils::generate_deterministic_keypairs, Attestation, AttesterSlashing, Keypair,
    MainnetEthSpec, ProposerSlashing, SignedBeaconBlock, SignedVoluntaryExit,
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

/// Skipping the slots around the epoch boundary allows us to check that we're obtaining states
/// from skipped slots for the finalized and justified checkpoints (instead of the state from the
/// block that those roots point to).
const SKIPPED_SLOTS: &[u64] = &[
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH - 1,
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH - 1,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH,
];

struct TestRig {
    chain: Arc<BeaconChain<T>>,
    next_block: SignedBeaconBlock<E>,
    attestations: Vec<Attestation<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    validator_keypairs: Vec<Keypair>,
    beacon_processor_tx: mpsc::Sender<WorkEvent<T>>,
    _network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    _sync_rx: mpsc::UnboundedReceiver<SyncMessage<E>>,
}

impl TestRig {
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
        .spawn_manager(beacon_processor_rx);

        Self {
            chain,
            next_block,
            attestations,
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            validator_keypairs: harness.validator_keypairs,
            beacon_processor_tx,
            _network_rx,
            _sync_rx,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn can_build_tester() {
    TestRig::new();
}
