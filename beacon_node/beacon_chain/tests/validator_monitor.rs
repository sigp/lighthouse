use lazy_static::lazy_static;

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::validator_monitor::{ValidatorMonitorConfig, MISSED_BLOCK_LAG_SLOTS};
use types::{Epoch, EthSpec, Hash256, Keypair, MainnetEthSpec, PublicKeyBytes, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type E = MainnetEthSpec;

fn get_harness(
    validator_count: usize,
    validator_index_to_monitor: usize,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .validator_monitor_config(ValidatorMonitorConfig {
            validators: vec![PublicKeyBytes::from(
                KEYPAIRS[validator_index_to_monitor].pk.clone(),
            )],
            ..<_>::default()
        })
        .build();

    harness.advance_slot();

    harness
}

#[tokio::test]
async fn produces_missed_blocks() {
    let validator_count = 16;

    let slots_per_epoch = MainnetEthSpec::slots_per_epoch();

    let nb_epoch_to_simulate = Epoch::new(2);

    // Generate 63 slots (2 epochs * 32 slots per epoch - 1)
    let initial_blocks = slots_per_epoch * nb_epoch_to_simulate.as_u64() - 1;

    // The validator index of the validator that is 'supposed' to miss a block
    let mut validator_index_to_monitor = 1;

    // 1st scenario //
    //
    // missed block happens when slot and prev_slot are in the same epoch
    let harness1 = get_harness(validator_count, validator_index_to_monitor);
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
    let mut duplicate_block_root = *_state.block_roots().get(idx as usize).unwrap();
    let mut validator_indexes = _state.get_beacon_proposer_indices(&harness1.spec).unwrap();
    let mut validator_index = validator_indexes[slot_in_epoch.as_usize()];
    let mut proposer_shuffling_decision_root = _state
        .proposer_shuffling_decision_root(Hash256::zero())
        .unwrap();

    let beacon_proposer_cache = harness1
        .chain
        .validator_monitor
        .read()
        .get_beacon_proposer_cache();

    // Let's fill the cache with the proposers for the current epoch
    // and push the duplicate_block_root to the block_roots vector
    assert_eq!(
        beacon_proposer_cache.lock().insert(
            epoch,
            proposer_shuffling_decision_root,
            validator_indexes.into_iter().collect::<Vec<usize>>(),
            _state.fork()
        ),
        Ok(())
    );

    // Modify the block root of the previous slot to be the same as the block root of the current slot
    // in order to simulate a missed block
    assert_eq!(
        _state.set_block_root(prev_slot, duplicate_block_root),
        Ok(())
    );

    {
        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        let mut validator_monitor = harness1.chain.validator_monitor.write();
        validator_monitor.process_valid_state(nb_epoch_to_simulate, _state);

        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor.get_monitored_validator_missed_block_count(validator_index as u64),
            1
        );
    }

    // 2nd scenario //
    //
    // missed block happens when slot and prev_slot are not in the same epoch
    // making sure that the cache reloads when the epoch changes
    // in that scenario the slot that missed a block is the first slot of the epoch
    validator_index_to_monitor = 7;
    let harness2 = get_harness(validator_count, validator_index_to_monitor);
    let advance_slot_by = 9;
    harness2
        .extend_chain(
            (initial_blocks + advance_slot_by) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let mut _state2 = &mut harness2.get_current_state();
    epoch = _state2.current_epoch();

    // We have a total of 72 slots and we want slot 64 to be the missed block
    // and this is slot=64 in epoch=2
    idx = initial_blocks + (advance_slot_by) - 8;
    slot = Slot::new(idx);
    prev_slot = Slot::new(idx - 1);
    slot_in_epoch = slot % slots_per_epoch;
    duplicate_block_root = *_state2.block_roots().get(idx as usize).unwrap();
    validator_indexes = _state2.get_beacon_proposer_indices(&harness2.spec).unwrap();
    validator_index = validator_indexes[slot_in_epoch.as_usize()];

    let beacon_proposer_cache = harness2
        .chain
        .validator_monitor
        .read()
        .get_beacon_proposer_cache();

    // Let's fill the cache with the proposers for the current epoch
    // and push the duplicate_block_root to the block_roots vector
    assert_eq!(
        beacon_proposer_cache.lock().insert(
            epoch,
            duplicate_block_root,
            validator_indexes.into_iter().collect::<Vec<usize>>(),
            _state2.fork()
        ),
        Ok(())
    );

    assert_eq!(
        _state2.set_block_root(prev_slot, duplicate_block_root),
        Ok(())
    );

    {
        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        let mut validator_monitor2 = harness2.chain.validator_monitor.write();
        validator_monitor2.process_valid_state(epoch, _state2);

        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor2.get_monitored_validator_missed_block_count(validator_index as u64),
            1
        );

        // 3rd scenario //
        //
        // a missed block happens but the validator is not monitored
        // it should not be flagged as a missed block
        idx = initial_blocks + (advance_slot_by) - 7;
        slot = Slot::new(idx);
        prev_slot = Slot::new(idx - 1);
        slot_in_epoch = slot % slots_per_epoch;
        duplicate_block_root = *_state2.block_roots().get(idx as usize).unwrap();
        validator_indexes = _state2.get_beacon_proposer_indices(&harness2.spec).unwrap();
        let not_monitored_validator_index = validator_indexes[slot_in_epoch.as_usize()];

        assert_eq!(
            _state2.set_block_root(prev_slot, duplicate_block_root),
            Ok(())
        );

        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        validator_monitor2.process_valid_state(epoch, _state2);

        // We shouldn't have any entry in the missed blocks map
        assert_ne!(validator_index, not_monitored_validator_index);
        assert_eq!(
            validator_monitor2
                .get_monitored_validator_missed_block_count(not_monitored_validator_index as u64),
            0
        );
    }

    // 4th scenario //
    //
    // a missed block happens but it happens but it's happening at state.slot - LOG_SLOTS_PER_EPOCH
    // it shouldn't be flagged as a missed block
    let harness3 = get_harness(validator_count, validator_index_to_monitor);
    harness3
        .extend_chain(
            slots_per_epoch as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let mut _state3 = &mut harness3.get_current_state();
    epoch = _state3.current_epoch();

    // We have a total of 32 slots and we want slot 30 to be a missed block
    // and this is slot=30 in epoch=0
    idx = slots_per_epoch - MISSED_BLOCK_LAG_SLOTS as u64 + 2;
    slot = Slot::new(idx);
    slot_in_epoch = slot % slots_per_epoch;
    prev_slot = Slot::new(idx - 1);
    duplicate_block_root = *_state3.block_roots().get(idx as usize).unwrap();
    validator_indexes = _state3.get_beacon_proposer_indices(&harness3.spec).unwrap();
    validator_index = validator_indexes[slot_in_epoch.as_usize()];
    proposer_shuffling_decision_root = _state3
        .proposer_shuffling_decision_root_at_epoch(epoch, Hash256::zero())
        .unwrap();

    let beacon_proposer_cache = harness3
        .chain
        .validator_monitor
        .read()
        .get_beacon_proposer_cache();

    // Let's fill the cache with the proposers for the current epoch
    // and push the duplicate_block_root to the block_roots vector
    assert_eq!(
        beacon_proposer_cache.lock().insert(
            epoch,
            proposer_shuffling_decision_root,
            validator_indexes.into_iter().collect::<Vec<usize>>(),
            _state3.fork()
        ),
        Ok(())
    );

    // Modify the block root of the previous slot to be the same as the block root of the current slot
    // in order to simulate a missed block
    assert_eq!(
        _state3.set_block_root(prev_slot, duplicate_block_root),
        Ok(())
    );

    {
        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        let mut validator_monitor3 = harness3.chain.validator_monitor.write();
        validator_monitor3.process_valid_state(epoch, _state3);

        // We shouldn't have one entry in the missed blocks map
        assert_eq!(
            validator_monitor3.get_monitored_validator_missed_block_count(validator_index as u64),
            0
        );
    }
}
