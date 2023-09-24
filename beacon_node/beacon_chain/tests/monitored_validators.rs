#![cfg(not(debug_assertions))]
use std::borrow::BorrowMut;
use std::ops::Deref;
use std::sync::Arc;
use futures::AsyncWriteExt;
use beacon_chain::validator_monitor::{MISSED_BLOCK_LAG_SLOTS, ValidatorMonitor};
use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        OP_POOL_DB_KEY,
    },
    BeaconChain, ChainConfig, NotifyExecutionLayer, StateSkipConfig, WhenSlotSkipped,
};
use lazy_static::lazy_static;
use beacon_chain::otb_verification_service::validate_optimistic_transition_blocks;
use operation_pool::PersistedOperationPool;
use state_processing::{
    per_slot_processing, per_slot_processing::Error as SlotProcessingError, EpochProcessingError,
};
use parking_lot::{Mutex, RwLock};
use types::{BeaconState, BeaconStateError, PublicKeyBytes, EthSpec, Hash256, Keypair, MinimalEthSpec, RelativeEpoch, Slot, Epoch, SignedBeaconBlock, MainnetEthSpec, ChainSpec};
use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use beacon_chain::validator_monitor::DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD;
use sloggers::{null::NullLoggerBuilder, Build};
use slog::{Logger};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type E = MainnetEthSpec;

fn get_logger() -> Logger {
    let builder = NullLoggerBuilder;
    builder.build().expect("should build logger")
}

fn get_harness(validator_count: usize, validator_index_to_monitor: usize, beacon_proposer_cache: BeaconProposerCache) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(E)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .beacon_proposer_cache(beacon_proposer_cache.clone())
        .validator_monitor(ValidatorMonitor::new(
            vec![
                PublicKeyBytes::from(KEYPAIRS[validator_index_to_monitor].pk),
            ],
            false,
            DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD,
            beacon_proposer_cache,
            get_logger()),
        )
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn produces_missed_blocks() {
    let log = get_logger();

    let validator_count = 16;
    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    let slots_per_epoch = MainnetEthSpec::slots_per_epoch();

    let missed_block_epoch = Epoch::new(2);
    let missed_block_slot = missed_block_epoch.start_slot(slots_per_epoch);

    // Generate 63 slots (2 epochs * 32 slots per epoch - 1)
    let initial_blocks = slots_per_epoch * missed_block_epoch.as_u64() - 1;
    println!("initial_blocks: {:?}", initial_blocks);

    // Mock the beacon proposer cache
    let mut beacon_proposer_cache = Arc::new(Mutex::new(<_>::default()));

    // The validator index of the validator that is 'supposed' to miss a block
    let mut validator_index_to_monitor = 1;


    // 1st scenario
    // missed block happens when slot and prev_slot are in the same epoch
    let harness1 = get_harness(validator_count, validator_index_to_monitor, beacon_proposer_cache.clone());
    harness1
        .extend_chain(
            initial_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let mut _state = &mut harness1.get_current_state();
    let mut epoch = _state.current_epoch();

    // We have a total of 63 slots and we want slot 57 to be a missed block
    // and this is slot=25 in epoch=1
    let mut idx = initial_blocks - 6;
    let mut slot = Slot::new(idx);
    let mut slot_in_epoch = slot % slots_per_epoch;
    let mut prev_slot = Slot::new(idx - 1);
    let mut duplicate_block_root = _state.block_roots().get(idx as usize).unwrap().clone();
    let mut validator_indexes = _state.get_beacon_proposer_indices(&harness1.spec).unwrap();
    let mut validator_index = validator_indexes[slot_in_epoch.as_usize()];
    let mut proposer_shuffling_decision_root = _state.proposer_shuffling_decision_root(epoch, Hash256::zero()).unwrap();

    // Let's fill the cache with the proposers for the current epoch
    // The proposers are the validators with indexes [11, 4, 6, 4, 6, 8]
    // with 11 the validator index of the first slot of the current epoch
    assert_eq!(
        beacon_proposer_cache
        .lock()
        .insert(
            epoch,
            proposer_shuffling_decision_root,
            validator_indexes.iter().map(|i| *i).collect::<Vec<usize>>(),
            _state.fork()
        ), Ok(()));

    // Modify the block root of the previous slot to be the same as the block root of the current slot
    // in order to simulate a missed block
    assert_eq!(_state.set_block_root(prev_slot, duplicate_block_root), Ok(()));

    // Let's validate the state which will call the function responsible for
    // adding the missed blocks to the validator monitor
    let mut validator_monitor = harness1.chain.validator_monitor.write();
    validator_monitor.process_valid_state(missed_block_epoch, _state);

    // We should have one entry in the missed blocks map
    assert_eq!(validator_monitor.get_monitored_validator_missed_block_count(validator_index as u64), 1);


    // 2nd scenario
    // missed block happens when slot and prev_slot are not in the same epoch
    // making sure that the cache reloads when the epoch changes
    // in that scenario the slot that missed a block is the first slot of the epoch
    validator_index_to_monitor = 7;
    let harness2 = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .beacon_proposer_cache(beacon_proposer_cache.clone())
        .validator_monitor(ValidatorMonitor::new(
            vec![
                PublicKeyBytes::from(KEYPAIRS[validator_index_to_monitor].pk.clone()),
            ],
            false,
            DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD,
            beacon_proposer_cache.clone(),
            log.clone(),
        ),
        )
        .build();
    harness2.advance_slot();

    let advance_slot_by = 9;
    harness2
        .extend_chain(
            (initial_blocks + advance_slot_by) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let mut _state2 = &mut harness2.get_current_state();
    let mut epoch2 = _state2.current_epoch();

    // We have a total of 72 slots and we want slot 64 to be the missed block
    // and this is slot=64 in epoch=2
    idx = initial_blocks + (advance_slot_by as u64) - 8;
    slot = Slot::new(idx);
    prev_slot = Slot::new(idx - 1);
    slot_in_epoch = slot % slots_per_epoch;
    duplicate_block_root = _state2.block_roots().get(idx as usize).unwrap().clone();
    validator_indexes = _state2.get_beacon_proposer_indices(&harness2.spec).unwrap();
    validator_index = validator_indexes[slot_in_epoch.as_usize()];
    proposer_shuffling_decision_root = _state2.proposer_shuffling_decision_root(epoch2, Hash256::zero()).unwrap();

    // println!("key pair: {:?}", KEYPAIRS[0..validator_count].to_vec());
    println!("harness2 current_epoch: {:?}", epoch2);
    println!("proposer_shuffling_decision_root: {:?}", proposer_shuffling_decision_root);
    println!("duplicate_block_root: {:?}", duplicate_block_root);
    println!("validator_index: {:?}", validator_index);
    println!("validator_indexes: {:?}", validator_indexes);

    // Let's fill the cache with the proposers for the current epoch
    // The proposers are the validators with indexes [1, 15, 5, 4, 9, 7, 7, 10]
    // with 11 the validator index of the first slot of the current epoch
    assert_eq!(
        beacon_proposer_cache
            .lock()
            .insert(
                epoch2,
                duplicate_block_root,
                validator_indexes.iter().map(|i| *i).collect::<Vec<usize>>(),
                _state2.fork()
            ), Ok(()));

    assert_eq!(_state2.set_block_root(prev_slot, duplicate_block_root), Ok(()));

    // Let's validate the state which will call the function responsible for
    // adding the missed blocks to the validator monitor
    let mut validator_monitor = harness2.chain.validator_monitor.write();
    validator_monitor.process_valid_state(epoch2, _state2);

    // We should have one entry in the missed blocks map
    assert_eq!(validator_monitor.get_monitored_validator_missed_block_count(validator_index as u64), 1);


    // 3rd scenario
    // a missed block happens but the validator is not monitored
    idx = initial_blocks + (advance_slot_by as u64) - 7;
    slot = Slot::new(idx);
    prev_slot = Slot::new(idx - 1);
    slot_in_epoch = slot % slots_per_epoch;
    duplicate_block_root = _state2.block_roots().get(idx as usize).unwrap().clone();
    validator_indexes = _state2.get_beacon_proposer_indices(&harness2.spec).unwrap();
    let not_monitored_validator_index = validator_indexes[slot_in_epoch.as_usize()];
    proposer_shuffling_decision_root = _state2.proposer_shuffling_decision_root(epoch2, Hash256::zero()).unwrap();

    assert_eq!(_state2.set_block_root(prev_slot, duplicate_block_root), Ok(()));

    // Let's validate the state which will call the function responsible for
    // adding the missed blocks to the validator monitor
    validator_monitor.process_valid_state(epoch2, _state2);

    // We shouldn't have any entry in the missed blocks map
    assert_eq!(validator_index != not_monitored_validator_index, true);
    assert_eq!(validator_monitor.get_monitored_validator_missed_block_count(not_monitored_validator_index as u64), 0);


    // 4th scenario
    // a missed block happens but it happens but it's happening at state.slot - LOG_SLOTS_PER_EPOCH
    // it shouldn't be flagged as a missed block
    let harness3 = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .beacon_proposer_cache(beacon_proposer_cache.clone())
        .validator_monitor(ValidatorMonitor::new(
            vec![],
            false,
            DEFAULT_INDIVIDUAL_TRACKING_THRESHOLD,
            beacon_proposer_cache.clone(),
            log.clone(),
        ),
        )
        .build();

    harness3.advance_slot();
    harness3
        .extend_chain(
            slots_per_epoch as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let mut _state3 = &mut harness3.get_current_state();
    let mut epoch3 = _state3.current_epoch();

    // We have a total of 32 slots and we want slot 30 to be a missed block
    // and this is slot=30 in epoch=0
    let mut idx = slots_per_epoch - MISSED_BLOCK_LAG_SLOTS as u64 + 2;
    let mut slot = Slot::new(idx);
    let mut slot_in_epoch = slot % slots_per_epoch;
    let mut prev_slot = Slot::new(idx - 1);
    let mut duplicate_block_root = _state3.block_roots().get(idx as usize).unwrap().clone();
    let mut validator_indexes = _state3.get_beacon_proposer_indices(&harness3.spec).unwrap();
    let mut validator_index = validator_indexes[slot_in_epoch.as_usize()];
    let mut proposer_shuffling_decision_root = _state3.proposer_shuffling_decision_root(epoch, Hash256::zero()).unwrap();

    // Let's fill the cache with the proposers for the current epoch
    assert_eq!(
        beacon_proposer_cache
            .lock()
            .insert(
                epoch3,
                proposer_shuffling_decision_root,
                validator_indexes.iter().map(|i| *i).collect::<Vec<usize>>(),
                _state3.fork()
            ), Ok(()));

    // Modify the block root of the previous slot to be the same as the block root of the current slot
    // in order to simulate a missed block
    assert_eq!(_state3.set_block_root(prev_slot, duplicate_block_root), Ok(()));

    // Let's validate the state which will call the function responsible for
    // adding the missed blocks to the validator monitor
    let mut validator_monitor = harness3.chain.validator_monitor.write();
    validator_monitor.process_valid_state(epoch3, _state3);

    // We should have one entry in the missed blocks map
    assert_eq!(validator_monitor.get_monitored_validator_missed_block_count(validator_index as u64), 0);
}
