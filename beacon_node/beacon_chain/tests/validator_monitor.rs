use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    NotifyExecutionLayer,
};
use beacon_chain::validator_monitor::{MISSED_BLOCK_LAG_SLOTS, ValidatorMonitorConfig};
use bls::{Keypair, PublicKeyBytes};
use std::sync::LazyLock;
use types::{BlockImportSource, Epoch, EthSpec, Hash256, MainnetEthSpec, Slot};

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
    let genesis_state = harness.get_current_state();
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
        .add_attested_blocks_at_slots(genesis_state, &slots, &all_validators)
        .await;

    // Prime the proposer shuffling cache.
    let mut proposer_shuffling_cache = harness.chain.beacon_proposer_cache.lock();
    for epoch in [0, 1].into_iter().map(Epoch::new) {
        let start_slot = epoch.start_slot(slots_per_epoch) + 1;
        let state = harness
            .get_hot_state(state_roots_by_slot[&start_slot])
            .unwrap();
        let decision_root = state
            .proposer_shuffling_decision_root(genesis_block_root, &harness.chain.spec)
            .unwrap();
        proposer_shuffling_cache
            .insert(
                epoch,
                decision_root,
                state
                    .get_beacon_proposer_indices(epoch, &harness.chain.spec)
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
    vm_write.process_valid_state(
        head_state.current_epoch(),
        &head_state,
        &harness.chain.spec,
        true,
    );
    // Start monitoring the innocent validator.
    vm_write.add_validator_pubkey(KEYPAIRS[innocent_proposer as usize].pk.compress());
    // Check for missed blocks.
    vm_write.process_valid_state(
        head_state.current_epoch(),
        &head_state,
        &harness.chain.spec,
        true,
    );

    // My client is innocent, your honour!
    assert_eq!(
        vm_write.get_monitored_validator_missed_block_count(innocent_proposer),
        0
    );
}

#[tokio::test]
async fn missed_blocks_basic() {
    // >= 32 validators required for Gloas genesis with MainnetEthSpec (32 slots/epoch).
    let validator_count = 32;

    let slots_per_epoch = E::slots_per_epoch();

    let nb_epoch_to_simulate = Epoch::new(2);

    // Generate 63 slots (2 epochs * 32 slots per epoch - 1)
    let initial_blocks = slots_per_epoch * nb_epoch_to_simulate.as_u64() - 1;

    // 1st scenario //
    //
    // Missed block happens when slot and prev_slot are in the same epoch
    let harness1 = get_harness(validator_count, vec![]);
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
    let mut validator_indexes = _state
        .get_beacon_proposer_indices(epoch, &harness1.spec)
        .unwrap();
    let mut missed_block_proposer = validator_indexes[slot_in_epoch.as_usize()];
    let mut proposer_shuffling_decision_root = _state
        .proposer_shuffling_decision_root(duplicate_block_root, &harness1.chain.spec)
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
            validator_indexes,
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

        validator_monitor.add_validator_pubkey(KEYPAIRS[missed_block_proposer].pk.compress());
        validator_monitor.process_valid_state(
            nb_epoch_to_simulate,
            _state,
            &harness1.chain.spec,
            true,
        );

        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor
                .get_monitored_validator_missed_block_count(missed_block_proposer as u64),
            1,
        );
    }

    // 2nd scenario //
    //
    // Missed block happens when slot and prev_slot are not in the same epoch
    // making sure that the cache reloads when the epoch changes
    // in that scenario the slot that missed a block is the first slot of the epoch
    let harness2 = get_harness(validator_count, vec![]);
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
    validator_indexes = _state2
        .get_beacon_proposer_indices(epoch, &harness2.spec)
        .unwrap();
    missed_block_proposer = validator_indexes[slot_in_epoch.as_usize()];

    let beacon_proposer_cache = harness2
        .chain
        .validator_monitor
        .read()
        .get_beacon_proposer_cache();

    // Let's fill the cache with the proposers for the current epoch
    // and push the duplicate_block_root to the block_roots vector
    assert_eq!(
        _state2.set_block_root(prev_slot, duplicate_block_root),
        Ok(())
    );

    let decision_block_root = _state2
        .proposer_shuffling_decision_root_at_epoch(epoch, Hash256::ZERO, &harness2.chain.spec)
        .unwrap();
    assert_eq!(
        beacon_proposer_cache.lock().insert(
            epoch,
            decision_block_root,
            validator_indexes.clone(),
            _state2.fork()
        ),
        Ok(())
    );

    {
        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        let mut validator_monitor2 = harness2.chain.validator_monitor.write();
        validator_monitor2.add_validator_pubkey(KEYPAIRS[missed_block_proposer].pk.compress());
        validator_monitor2.process_valid_state(epoch, _state2, &harness2.chain.spec, true);
        // We should have one entry in the missed blocks map
        assert_eq!(
            validator_monitor2
                .get_monitored_validator_missed_block_count(missed_block_proposer as u64),
            1
        );

        // 3rd scenario //
        //
        // A missed block happens but the validator is not monitored
        // it should not be flagged as a missed block
        while validator_indexes[(idx % slots_per_epoch) as usize] == missed_block_proposer
            && idx / slots_per_epoch == epoch.as_u64()
        {
            idx += 1;
        }
        slot = Slot::new(idx);
        prev_slot = Slot::new(idx - 1);
        slot_in_epoch = slot % slots_per_epoch;
        duplicate_block_root = *_state2.block_roots().get(idx as usize).unwrap();
        let second_missed_block_proposer = validator_indexes[slot_in_epoch.as_usize()];

        // This test may fail if we can't find another distinct proposer in the same epoch.
        // However, this should be vanishingly unlikely: P ~= (1/16)^32 = 2e-39.
        assert_ne!(missed_block_proposer, second_missed_block_proposer);

        assert_eq!(
            _state2.set_block_root(prev_slot, duplicate_block_root),
            Ok(())
        );

        // Let's validate the state which will call the function responsible for
        // adding the missed blocks to the validator monitor
        validator_monitor2.process_valid_state(epoch, _state2, &harness2.chain.spec, true);

        // We shouldn't have any entry in the missed blocks map
        assert_eq!(
            validator_monitor2
                .get_monitored_validator_missed_block_count(second_missed_block_proposer as u64),
            0
        );
    }

    // 4th scenario //
    //
    // A missed block happens at state.slot - LOG_SLOTS_PER_EPOCH
    // it shouldn't be flagged as a missed block
    let harness3 = get_harness(validator_count, vec![]);
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
    validator_indexes = _state3
        .get_beacon_proposer_indices(epoch, &harness3.spec)
        .unwrap();
    missed_block_proposer = validator_indexes[slot_in_epoch.as_usize()];
    proposer_shuffling_decision_root = _state3
        .proposer_shuffling_decision_root_at_epoch(
            epoch,
            duplicate_block_root,
            &harness1.chain.spec,
        )
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
            validator_indexes,
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
        validator_monitor3.add_validator_pubkey(KEYPAIRS[missed_block_proposer].pk.compress());
        validator_monitor3.process_valid_state(epoch, _state3, &harness3.chain.spec, true);

        // We shouldn't have one entry in the missed blocks map
        assert_eq!(
            validator_monitor3
                .get_monitored_validator_missed_block_count(missed_block_proposer as u64),
            0
        );
    }
}

// Regression test for false-positive missed block logging from side chains (issue #8080).
#[tokio::test]
async fn missed_blocks_ignore_non_canonical_states() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();

    let harness = get_harness(VALIDATOR_COUNT, vec![]);
    let validator_monitor = &harness.chain.validator_monitor;
    let genesis_state = harness.get_current_state();

    // Build a canonical chain with a block in every slot. Keep the state at the last slot of epoch
    // 0 around so that the side chain below can fork from it.
    let fork_slot = Slot::new(slots_per_epoch as u64 - 1);
    let tip_slot = Slot::new(slots_per_epoch as u64 + 8);
    let slots = (1..=tip_slot.as_u64()).map(Slot::new).collect::<Vec<_>>();
    let (_, state_roots_by_slot, _, head_state) = harness
        .add_attested_blocks_at_slots(genesis_state, &slots, &all_validators)
        .await;

    // Watch the proposer of a slot in epoch 1 that the canonical chain proposed a block for, but
    // which the side chain below will report as skipped.
    let epoch = Epoch::new(1);
    let victim_slot = Slot::new(slots_per_epoch as u64 + 2);
    let victim_proposer = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap()[victim_slot.as_usize() % slots_per_epoch];

    // The proposer shuffling cache is keyed by the block root at the end of the previous epoch.
    // Both chains share that block, because they fork after it.
    let decision_root = head_state
        .proposer_shuffling_decision_root_at_epoch(
            epoch,
            harness.head_block_root(),
            &harness.chain.spec,
        )
        .unwrap();
    let proposers = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap();
    harness
        .chain
        .beacon_proposer_cache
        .lock()
        .insert(epoch, decision_root, proposers, head_state.fork())
        .unwrap();

    {
        let mut vm_write = validator_monitor.write();
        // Ensure the monitor knows every validator's index, then start monitoring the victim.
        vm_write.process_valid_state(
            head_state.current_epoch(),
            &head_state,
            &harness.chain.spec,
            true,
        );
        vm_write.add_validator_pubkey(KEYPAIRS[victim_proposer].pk.compress());
    }

    // Import a side chain block at the canonical tip, built on the state at the end of epoch 0.
    // Slots `slots_per_epoch .. tip_slot` are skipped on this chain, but every one of them was
    // proposed on the canonical chain.
    let fork_state = harness
        .get_hot_state(state_roots_by_slot[&fork_slot])
        .unwrap();
    harness
        .add_block_at_slot(tip_slot, fork_state)
        .await
        .expect("side chain block should import");

    assert_eq!(
        validator_monitor
            .read()
            .get_monitored_validator_missed_block_count(victim_proposer as u64),
        0,
        "side chain import must not report a missed block for a slot proposed on the canonical chain"
    );
}

// A canonical block more than `EARLY_ATTESTER_CACHE_HISTORIC_SLOTS` behind the wall clock must
// still be used for missed block detection (issue #8080).
#[tokio::test]
async fn missed_blocks_detected_for_stale_canonical_blocks() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();

    let harness = get_harness(VALIDATOR_COUNT, vec![]);
    let validator_monitor = &harness.chain.validator_monitor;
    let genesis_state = harness.get_current_state();

    // Build a canonical chain with a genuinely missed block at offset 2 of epoch 1.
    let missed_slot = Slot::new(slots_per_epoch as u64 + 2);
    let tip_slot = Slot::new(slots_per_epoch as u64 + 8);
    let slots = (1..=tip_slot.as_u64())
        .map(Slot::new)
        .filter(|slot| *slot != missed_slot)
        .collect::<Vec<_>>();
    let (_, _, _, head_state) = harness
        .add_attested_blocks_at_slots(genesis_state, &slots, &all_validators)
        .await;

    let epoch = missed_slot.epoch(E::slots_per_epoch());
    let missed_proposer = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap()[missed_slot.as_usize() % slots_per_epoch];

    // Prime the proposer cache so that missed block detection can resolve the proposer.
    let decision_root = head_state
        .proposer_shuffling_decision_root_at_epoch(
            epoch,
            harness.head_block_root(),
            &harness.chain.spec,
        )
        .unwrap();
    let proposers = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap();
    harness
        .chain
        .beacon_proposer_cache
        .lock()
        .insert(epoch, decision_root, proposers, head_state.fork())
        .unwrap();

    // Only start monitoring now, so that building the chain above cannot have recorded the missed
    // block already.
    {
        let mut vm_write = validator_monitor.write();
        vm_write.process_valid_state(
            head_state.current_epoch(),
            &head_state,
            &harness.chain.spec,
            true,
        );
        vm_write.add_validator_pubkey(KEYPAIRS[missed_proposer].pk.compress());
        assert_eq!(
            vm_write.get_monitored_validator_missed_block_count(missed_proposer as u64),
            0,
            "the missed block must not have been recorded while building the chain"
        );
    }

    // Build a canonical block on top of the tip, but import it with the wall clock advanced past
    // it, so that it is stale by more than `EARLY_ATTESTER_CACHE_HISTORIC_SLOTS`.
    let block_slot = tip_slot + 1u64;
    let (block_contents, _, _) = harness
        .make_block_with_envelope(head_state.clone(), block_slot)
        .await;
    let block_root = block_contents.0.canonical_root();
    harness.set_current_slot(Slot::new(block_slot.as_u64() + 6));

    let range_sync_block = harness
        .build_range_sync_block_from_blobs(block_contents.0.clone(), block_contents.1.clone())
        .unwrap();
    harness
        .chain
        .process_block(
            block_root,
            range_sync_block,
            NotifyExecutionLayer::Yes,
            BlockImportSource::RangeSync,
            || Ok(()),
        )
        .await
        .expect("stale canonical block should import");

    // The stale block's state still covers the missed slot, so it must be reported.
    assert_eq!(
        validator_monitor
            .read()
            .get_monitored_validator_missed_block_count(missed_proposer as u64),
        1,
        "a stale canonical block must still report the missed block it exposes"
    );
}

// A missed slot is not lost just because the first block that would have covered it was a side
// chain: a later canonical block still covers it (issue #8080).
#[tokio::test]
async fn missed_blocks_reported_by_later_canonical_block() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let all_validators = (0..VALIDATOR_COUNT).collect::<Vec<_>>();

    let harness = get_harness(VALIDATOR_COUNT, vec![]);
    let validator_monitor = &harness.chain.validator_monitor;
    let genesis_state = harness.get_current_state();

    // Canonical chain with slot 34 missed, and the state at the end of epoch 0 kept for forking.
    let missed_slot = Slot::new(slots_per_epoch as u64 + 2);
    let fork_slot = Slot::new(slots_per_epoch as u64 - 1);
    let tip_slot = Slot::new(slots_per_epoch as u64 + 8);
    let slots = (1..=tip_slot.as_u64())
        .map(Slot::new)
        .filter(|slot| *slot != missed_slot)
        .collect::<Vec<_>>();
    let (_, state_roots_by_slot, _, head_state) = harness
        .add_attested_blocks_at_slots(genesis_state, &slots, &all_validators)
        .await;

    let epoch = missed_slot.epoch(E::slots_per_epoch());
    let missed_proposer = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap()[missed_slot.as_usize() % slots_per_epoch];

    // Prime the proposer cache so that missed block detection can resolve the proposer.
    let decision_root = head_state
        .proposer_shuffling_decision_root_at_epoch(
            epoch,
            harness.head_block_root(),
            &harness.chain.spec,
        )
        .unwrap();
    let proposers = head_state
        .get_beacon_proposer_indices(epoch, &harness.chain.spec)
        .unwrap();
    harness
        .chain
        .beacon_proposer_cache
        .lock()
        .insert(epoch, decision_root, proposers, head_state.fork())
        .unwrap();

    // Only start monitoring now, so that building the chain above cannot have recorded the missed
    // block already.
    {
        let mut vm_write = validator_monitor.write();
        vm_write.process_valid_state(
            head_state.current_epoch(),
            &head_state,
            &harness.chain.spec,
            true,
        );
        vm_write.add_validator_pubkey(KEYPAIRS[missed_proposer].pk.compress());
    }

    let next_slot = tip_slot + 1u64;

    // A side chain block at `next_slot` skips `missed_slot` as well, but must not report it.
    let fork_state = harness
        .get_hot_state(state_roots_by_slot[&fork_slot])
        .unwrap();
    harness
        .add_block_at_slot(next_slot, fork_state)
        .await
        .expect("side chain block should import");
    assert_eq!(
        validator_monitor
            .read()
            .get_monitored_validator_missed_block_count(missed_proposer as u64),
        0,
        "the side chain block must not report the missed block"
    );

    // The canonical block at the same slot covers the missed slot, so it must report it.
    harness
        .add_block_at_slot(next_slot, head_state.clone())
        .await
        .expect("canonical block should import");
    assert_eq!(
        validator_monitor
            .read()
            .get_monitored_validator_missed_block_count(missed_proposer as u64),
        1,
        "a later canonical block must still report the missed block"
    );
}
