use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
};
use beacon_chain::validator_monitor::{ValidatorMonitorConfig, MISSED_BLOCK_LAG_SLOTS};
use logging::test_logger;
use std::sync::LazyLock;
use types::{Epoch, EthSpec, ForkName, Keypair, MainnetEthSpec, PublicKeyBytes, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

type E = MainnetEthSpec;

fn get_harness(
    validator_count: usize,
    validator_indexes_to_monitor: Vec<usize>,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .logger(test_logger())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .validator_monitor_config(ValidatorMonitorConfig {
            validators: validator_indexes_to_monitor
                .iter()
                .map(|i| PublicKeyBytes::from(KEYPAIRS[*i].pk.clone()))
                .collect(),
            ..<_>::default()
        })
        .build();

    harness.advance_slot();

    harness
}

// Regression test for off-by-one caching issue in missed block detection.
#[tokio::test]
async fn missed_blocks_across_epochs() {
    let slots_per_epoch = E::slots_per_epoch();
    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();

    let harness = get_harness(VALIDATOR_COUNT, vec![]);
    let validator_monitor = &harness.chain.validator_monitor;
    let mut genesis_state = harness.get_current_state();
    let genesis_state_root = genesis_state.update_tree_hash_cache().unwrap();
    let genesis_block_root = harness.head_block_root();

    // Skip a slot in the first epoch (to prime the cache inside the missed block function) and then
    // at a different offset in the 2nd epoch. The missed block in the 2nd epoch MUST NOT reuse
    // the cache from the first epoch.
    let first_skip_offset = 3;
    let second_skip_offset = slots_per_epoch / 2;
    assert_ne!(first_skip_offset, second_skip_offset);
    let first_skip_slot = Slot::new(first_skip_offset);
    let second_skip_slot = Slot::new(slots_per_epoch + second_skip_offset);
    let slots = (1..2 * slots_per_epoch)
        .map(Slot::new)
        .filter(|slot| *slot != first_skip_slot && *slot != second_skip_slot)
        .collect::<Vec<_>>();

    let (block_roots_by_slot, state_roots_by_slot, _, head_state) = harness
        .add_attested_blocks_at_slots(genesis_state, genesis_state_root, &slots, &all_validators)
        .await;

    // Prime the proposer shuffling cache.
    let mut proposer_shuffling_cache = harness.chain.beacon_proposer_cache.lock();
    for epoch in [0, 1].into_iter().map(Epoch::new) {
        let start_slot = epoch.start_slot(slots_per_epoch) + 1;
        let state = harness
            .get_hot_state(state_roots_by_slot[&start_slot])
            .unwrap();
        let decision_root = state
            .proposer_shuffling_decision_root(genesis_block_root)
            .unwrap();
        proposer_shuffling_cache
            .insert(
                epoch,
                decision_root,
                state
                    .get_beacon_proposer_indices(&harness.chain.spec)
                    .unwrap(),
                state.fork(),
            )
            .unwrap();
    }
    drop(proposer_shuffling_cache);

    // Monitor the validator that proposed the block at the same offset in the 0th epoch as the skip
    // in the 1st epoch.
    let innocent_proposer_slot = Slot::new(second_skip_offset);
    let innocent_proposer = harness
        .get_block(block_roots_by_slot[&innocent_proposer_slot])
        .unwrap()
        .message()
        .proposer_index();

    let mut vm_write = validator_monitor.write();

    // Call `process_` once to update validator indices.
    vm_write.process_valid_state(head_state.current_epoch(), &head_state, &harness.chain.spec);
    // Start monitoring the innocent validator.
    vm_write.add_validator_pubkey(KEYPAIRS[innocent_proposer as usize].pk.compress());
    // Check for missed blocks.
    vm_write.process_valid_state(head_state.current_epoch(), &head_state, &harness.chain.spec);

    // My client is innocent, your honour!
    assert_eq!(
        vm_write.get_monitored_validator_missed_block_count(innocent_proposer),
        0
    );
}

#[tokio::test]
async fn produces_missed_blocks() {
    let validator_count = 16;

    let slots_per_epoch = E::slots_per_epoch();

    let nb_epoch_to_simulate = Epoch::new(2);

    // Generate 63 slots (2 epochs * 32 slots per epoch - 1)
    let initial_blocks = slots_per_epoch * nb_epoch_to_simulate.as_u64() - 1;

    // The validator index of the validator that is 'supposed' to miss a block
    let validator_index_to_monitor = 1;

    // 1st scenario //
    //
    // Missed block happens when slot and prev_slot are in the same epoch
    let harness1 = get_harness(validator_count, vec![validator_index_to_monitor]);
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
        .proposer_shuffling_decision_root(duplicate_block_root)
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
        validator_monitor.process_valid_state(nb_epoch_to_simulate, _state, &harness1.chain.spec);

        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor.get_monitored_validator_missed_block_count(validator_index as u64),
            1
        );
    }

    // 2nd scenario //
    //
    // Missed block happens when slot and prev_slot are not in the same epoch
    // making sure that the cache reloads when the epoch changes
    // in that scenario the slot that missed a block is the first slot of the epoch
    // We are adding other validators to monitor as these ones will miss a block depending on
    // the fork name specified when running the test as the proposer cache differs depending on
    // the fork name (cf. seed)
    //
    // If you are adding a new fork and seeing errors, print
    // `validator_indexes[slot_in_epoch.as_usize()]` and add it below.
    let validator_index_to_monitor = match harness1.spec.fork_name_at_slot::<E>(Slot::new(0)) {
        ForkName::Base => 7,
        ForkName::Altair => 2,
        ForkName::Bellatrix => 4,
        ForkName::Capella => 11,
        ForkName::Deneb => 3,
        ForkName::Electra => 1,
        ForkName::EIP7732 => 9,
    };

    let harness2 = get_harness(validator_count, vec![validator_index_to_monitor]);
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
    // If you are adding a new fork and seeing errors, it means the fork seed has changed the
    // validator_index. Uncomment this line, run the test again and add the resulting index to the
    // list above.
    //eprintln!("new index which needs to be added => {:?}", validator_index);

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
        validator_monitor2.process_valid_state(epoch, _state2, &harness2.chain.spec);
        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor2.get_monitored_validator_missed_block_count(validator_index as u64),
            1
        );

        // 3rd scenario //
        //
        // A missed block happens but the validator is not monitored
        // it should not be flagged as a missed block
        idx = initial_blocks + (advance_slot_by) - 7;
        slot = Slot::new(idx);
        prev_slot = Slot::new(idx - 1);
        slot_in_epoch = slot % slots_per_epoch;
        duplicate_block_root = *_state2.block_roots().get(idx as usize).unwrap();
        validator_indexes = _state2.get_beacon_proposer_indices(&harness2.spec).unwrap();
        let not_monitored_validator_index = validator_indexes[slot_in_epoch.as_usize()];
        // This could do with a refactor: https://github.com/sigp/lighthouse/issues/6293
        assert_ne!(
            not_monitored_validator_index,
            validator_index_to_monitor,
            "this test has a fragile dependency on hardcoded indices. you need to tweak some settings or rewrite this"
        );

        assert_eq!(
            _state2.set_block_root(prev_slot, duplicate_block_root),
            Ok(())
        );

        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        validator_monitor2.process_valid_state(epoch, _state2, &harness2.chain.spec);

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
    // A missed block happens at state.slot - LOG_SLOTS_PER_EPOCH
    // it shouldn't be flagged as a missed block
    let harness3 = get_harness(validator_count, vec![validator_index_to_monitor]);
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
        .proposer_shuffling_decision_root_at_epoch(epoch, duplicate_block_root)
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
        validator_monitor3.process_valid_state(epoch, _state3, &harness3.chain.spec);

        // We shouldn't have one entry in the missed blocks map
        assert_eq!(
            validator_monitor3.get_monitored_validator_missed_block_count(validator_index as u64),
            0
        );
    }
}
