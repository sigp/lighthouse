#![cfg(not(debug_assertions))]

use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
        OP_POOL_DB_KEY,
    },
    BeaconChain, NotifyExecutionLayer, StateSkipConfig, WhenSlotSkipped,
};
use lazy_static::lazy_static;
use operation_pool::PersistedOperationPool;
use state_processing::{
    per_slot_processing, per_slot_processing::Error as SlotProcessingError, EpochProcessingError,
};
use types::{
    BeaconState, BeaconStateError, EthSpec, Hash256, Keypair, MinimalEthSpec, RelativeEpoch, Slot,
};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 48;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>> {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

#[test]
fn massive_skips() {
    let harness = get_harness(8);
    let spec = &harness.chain.spec;
    let mut state = harness.chain.head_beacon_state_cloned();

    // Run per_slot_processing until it returns an error.
    let error = loop {
        match per_slot_processing(&mut state, None, spec) {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };

    assert!(state.slot() > 1, "the state should skip at least one slot");
    assert_eq!(
        error,
        SlotProcessingError::EpochProcessingError(EpochProcessingError::BeaconStateError(
            BeaconStateError::InsufficientValidators
        )),
        "should return error indicating that validators have been slashed out"
    )
}

#[tokio::test]
async fn iterators() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            // No need to produce attestations for this test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let block_roots: Vec<(Hash256, Slot)> = harness
        .chain
        .forwards_iter_block_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
        .collect();
    let state_roots: Vec<(Hash256, Slot)> = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
        .collect();

    assert_eq!(
        block_roots.len(),
        state_roots.len(),
        "should be an equal amount of block and state roots"
    );

    assert!(
        block_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis block root"
    );
    assert!(
        state_roots.iter().any(|(_root, slot)| *slot == 0),
        "should contain genesis state root"
    );

    assert_eq!(
        block_roots.len(),
        num_blocks_produced as usize + 1,
        "should contain all produced blocks, plus the genesis block"
    );

    block_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 + 1,
            "block root slots should be increasing by one"
        )
    });
    state_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 + 1,
            "state root slots should be increasing by one"
        )
    });

    let head = harness.chain.head_snapshot();

    assert_eq!(
        *block_roots.last().expect("should have some block roots"),
        (head.beacon_block_root, head.beacon_block.slot()),
        "last block root and slot should be for the head block"
    );

    assert_eq!(
        *state_roots.last().expect("should have some state roots"),
        (head.beacon_state_root(), head.beacon_state.slot()),
        "last state root and slot should be for the head state"
    );
}

fn find_reorg_slot(
    chain: &BeaconChain<EphemeralHarnessType<MinimalEthSpec>>,
    new_state: &BeaconState<MinimalEthSpec>,
    new_block_root: Hash256,
) -> Slot {
    let (old_state, old_block_root) = {
        let head = chain.canonical_head.cached_head();
        let old_state = head.snapshot.beacon_state.clone();
        let old_block_root = head.head_block_root();
        (old_state, old_block_root)
    };
    beacon_chain::canonical_head::find_reorg_slot(
        &old_state,
        old_block_root,
        new_state,
        new_block_root,
        &chain.spec,
    )
    .unwrap()
}

#[tokio::test]
async fn find_reorgs() {
    let num_blocks_produced = MinimalEthSpec::slots_per_historical_root() + 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            // No need to produce attestations for this test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let head_state = &head.beacon_state;
    let head_slot = head_state.slot();
    let genesis_state = harness
        .chain
        .state_at_slot(Slot::new(0), StateSkipConfig::WithStateRoots)
        .unwrap();

    // because genesis is more than `SLOTS_PER_HISTORICAL_ROOT` away, this should return with the
    // finalized slot.
    assert_eq!(
        find_reorg_slot(
            &harness.chain,
            &genesis_state,
            harness.chain.genesis_block_root
        ),
        head_state
            .finalized_checkpoint()
            .epoch
            .start_slot(MinimalEthSpec::slots_per_epoch())
    );

    // test head
    assert_eq!(
        find_reorg_slot(
            &harness.chain,
            &head_state,
            harness.chain.head_beacon_block().canonical_root()
        ),
        head_slot
    );

    // Re-org back to the slot prior to the head.
    let prev_slot = head_slot - Slot::new(1);
    let prev_state = harness
        .chain
        .state_at_slot(prev_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    let prev_block_root = harness
        .chain
        .block_root_at_slot(prev_slot, WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    assert_eq!(
        find_reorg_slot(&harness.chain, &prev_state, prev_block_root),
        prev_slot
    );
}

#[tokio::test]
async fn chooses_fork() {
    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let delay = MinimalEthSpec::default_spec().min_attestation_inclusion_delay as usize;

    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..VALIDATOR_COUNT).collect();

    let initial_blocks = delay + 1;
    let honest_fork_blocks = delay + 1;
    let faulty_fork_blocks = delay + 2;

    // Build an initial chain where all validators agree.
    harness
        .extend_chain(
            initial_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (honest_head, faulty_head) = harness
        .generate_two_forks_by_skipping_a_block(
            &honest_validators,
            &faulty_validators,
            honest_fork_blocks,
            faulty_fork_blocks,
        )
        .await;

    assert_ne!(honest_head, faulty_head, "forks should be distinct");

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        Slot::from(initial_blocks + honest_fork_blocks),
        "head should be at the current slot"
    );

    assert_eq!(
        harness.chain.head_snapshot().beacon_block_root,
        honest_head,
        "the honest chain should be the canonical chain"
    );
}

#[tokio::test]
async fn finalizes_with_full_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

#[tokio::test]
async fn finalizes_with_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let attesters = (0..two_thirds).collect();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );

    // Note: the 2/3rds tests are not justifying the immediately prior epochs because the
    // `MIN_ATTESTATION_INCLUSION_DELAY` is preventing an adequate number of attestations being
    // included in blocks during that epoch.

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be justified two behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 4,
        "the head should be finalized three behind the current epoch"
    );
}

#[tokio::test]
async fn does_not_finalize_with_less_than_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let less_than_two_thirds = two_thirds - 1;
    let attesters = (0..less_than_two_thirds).collect();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "no epoch should have been finalized"
    );
}

#[tokio::test]
async fn does_not_finalize_without_attestation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;

    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        0,
        "no epoch should have been finalized"
    );
}

#[tokio::test]
async fn roundtrip_operation_pool() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    // Add some attestations
    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    assert!(harness.chain.op_pool.num_attestations() > 0);

    // TODO: could add some other operations
    harness
        .chain
        .persist_op_pool()
        .expect("should persist op pool");

    let restored_op_pool = harness
        .chain
        .store
        .get_item::<PersistedOperationPool<MinimalEthSpec>>(&OP_POOL_DB_KEY)
        .expect("should read db")
        .expect("should find op pool")
        .into_operation_pool()
        .unwrap();

    assert_eq!(harness.chain.op_pool, restored_op_pool);
}

#[tokio::test]
async fn unaggregated_attestations_added_to_fork_choice_some_none() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() / 2;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let mut fork_choice = harness.chain.canonical_head.fork_choice_write_lock();

    // Move forward a slot so all queued attestations can be processed.
    harness.advance_slot();
    fork_choice
        .update_time(harness.chain.slot().unwrap())
        .unwrap();

    let validator_slots: Vec<(usize, Slot)> = (0..VALIDATOR_COUNT)
        .into_iter()
        .map(|validator_index| {
            let slot = state
                .get_attestation_duties(validator_index, RelativeEpoch::Current)
                .expect("should get attester duties")
                .unwrap()
                .slot;

            (validator_index, slot)
        })
        .collect();

    for (validator, slot) in validator_slots.clone() {
        let latest_message = fork_choice.latest_message(validator);

        if slot <= num_blocks_produced && slot != 0 {
            assert_eq!(
                latest_message.unwrap().1,
                slot.epoch(MinimalEthSpec::slots_per_epoch()),
                "Latest message epoch for {} should be equal to epoch {}.",
                validator,
                slot
            )
        } else {
            assert!(
                latest_message.is_none(),
                "Latest message slot should be None."
            )
        }
    }
}

#[tokio::test]
async fn attestations_with_increasing_slots() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let mut attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness
            .extend_chain(
                2,
                BlockStrategy::OnCanonicalHead,
                // Don't produce & include any attestations (we'll collect them later).
                AttestationStrategy::SomeValidators(vec![]),
            )
            .await;

        let head = harness.chain.head_snapshot();
        let head_state_root = head.beacon_state_root();

        attestations.extend(harness.get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &head.beacon_state,
            head_state_root,
            head.beacon_block_root,
            head.beacon_block.slot(),
        ));

        harness.advance_slot();
    }

    for (attestation, subnet_id) in attestations.into_iter().flatten() {
        let res = harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id));

        let current_slot = harness.chain.slot().expect("should get slot");
        let expected_attestation_slot = attestation.data.slot;
        let expected_earliest_permissible_slot =
            current_slot - MinimalEthSpec::slots_per_epoch() - 1;

        if expected_attestation_slot < expected_earliest_permissible_slot {
            assert!(matches!(
                res.err().unwrap(),
                AttnError::PastSlot {
                    attestation_slot,
                    earliest_permissible_slot,
                }
                if attestation_slot == expected_attestation_slot && earliest_permissible_slot == expected_earliest_permissible_slot
            ))
        } else {
            res.expect("should process attestation");
        }
    }
}

#[tokio::test]
async fn unaggregated_attestations_added_to_fork_choice_all_updated() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let state = &head.beacon_state;
    let mut fork_choice = harness.chain.canonical_head.fork_choice_write_lock();

    // Move forward a slot so all queued attestations can be processed.
    harness.advance_slot();
    fork_choice
        .update_time(harness.chain.slot().unwrap())
        .unwrap();

    let validators: Vec<usize> = (0..VALIDATOR_COUNT).collect();
    let slots: Vec<Slot> = validators
        .iter()
        .map(|&v| {
            state
                .get_attestation_duties(v, RelativeEpoch::Current)
                .expect("should get attester duties")
                .unwrap()
                .slot
        })
        .collect();
    let validator_slots: Vec<(&usize, Slot)> = validators.iter().zip(slots).collect();

    for (validator, slot) in validator_slots {
        let latest_message = fork_choice.latest_message(*validator);

        assert_eq!(
            latest_message.unwrap().1,
            slot.epoch(MinimalEthSpec::slots_per_epoch()),
            "Latest message slot should be equal to attester duty."
        );

        if slot != num_blocks_produced {
            let block_root = state
                .get_block_root(slot)
                .expect("Should get block root at slot");

            assert_eq!(
                latest_message.unwrap().0,
                *block_root,
                "Latest message block root should be equal to block at slot."
            );
        }
    }
}

async fn run_skip_slot_test(skip_slots: u64) {
    let num_validators = 8;
    let harness_a = get_harness(num_validators);
    let harness_b = get_harness(num_validators);

    for _ in 0..skip_slots {
        harness_a.advance_slot();
        harness_b.advance_slot();
    }

    harness_a
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            // No attestation required for test.
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    assert_eq!(
        harness_a.chain.head_snapshot().beacon_block.slot(),
        Slot::new(skip_slots + 1)
    );
    assert_eq!(
        harness_b.chain.head_snapshot().beacon_block.slot(),
        Slot::new(0)
    );

    assert_eq!(
        harness_b
            .chain
            .process_block(
                harness_a.chain.head_snapshot().beacon_block_root,
                harness_a.chain.head_snapshot().beacon_block.clone(),
                NotifyExecutionLayer::Yes,
                || Ok(())
            )
            .await
            .unwrap(),
        harness_a.chain.head_snapshot().beacon_block_root
    );

    harness_b.chain.recompute_head_at_current_slot().await;

    assert_eq!(
        harness_b.chain.head_snapshot().beacon_block.slot(),
        Slot::new(skip_slots + 1)
    );
}

#[tokio::test]
async fn produces_and_processes_with_genesis_skip_slots() {
    for i in 0..MinimalEthSpec::slots_per_epoch() * 4 {
        run_skip_slot_test(i).await
    }
}

#[tokio::test]
async fn block_roots_skip_slot_behaviour() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Test should be longer than the block roots to ensure a DB lookup is triggered.
    let chain_length = harness
        .chain
        .head_snapshot()
        .beacon_state
        .block_roots()
        .len() as u64
        * 3;

    let skipped_slots = [1, 6, 7, 10, chain_length];

    // Build a chain with some skip slots.
    for i in 1..=chain_length {
        if i > 1 {
            harness.advance_slot();
        }

        let slot = harness.chain.slot().unwrap().as_u64();

        if !skipped_slots.contains(&slot) {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
        }
    }

    let mut prev_unskipped_root = None;

    for target_slot in 0..=chain_length {
        if skipped_slots.contains(&target_slot) {
            /*
             * A skip slot
             */
            assert!(
                harness
                    .chain
                    .block_root_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .is_none(),
                "WhenSlotSkipped::None should return None on a skip slot"
            );

            let skipped_root = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                .unwrap()
                .expect("WhenSlotSkipped::Prev should always return Some");

            assert_eq!(
                skipped_root,
                prev_unskipped_root.expect("test is badly formed"),
                "WhenSlotSkipped::Prev should accurately return the prior skipped block"
            );

            let expected_block = harness
                .chain
                .get_blinded_block(&skipped_root)
                .unwrap()
                .unwrap();

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap(),
                expected_block,
            );

            assert!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .is_none(),
                "WhenSlotSkipped::None should return None on a skip slot"
            );
        } else {
            /*
             * Not a skip slot
             */
            let skips_none = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::None)
                .unwrap()
                .expect("WhenSlotSkipped::None should return Some for non-skipped block");
            let skips_prev = harness
                .chain
                .block_root_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                .unwrap()
                .expect("WhenSlotSkipped::Prev should always return Some");
            assert_eq!(
                skips_none, skips_prev,
                "WhenSlotSkipped::None and WhenSlotSkipped::Prev should be equal on non-skipped slot"
            );

            let expected_block = harness
                .chain
                .get_blinded_block(&skips_prev)
                .unwrap()
                .unwrap();

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::Prev)
                    .unwrap()
                    .unwrap(),
                expected_block
            );

            assert_eq!(
                harness
                    .chain
                    .block_at_slot(target_slot.into(), WhenSlotSkipped::None)
                    .unwrap()
                    .unwrap(),
                expected_block
            );

            prev_unskipped_root = Some(skips_prev);
        }
    }

    /*
     * A future, non-existent slot.
     */

    let future_slot = harness.chain.slot().unwrap() + 1;
    assert_eq!(
        harness.chain.head_snapshot().beacon_block.slot(),
        future_slot - 2,
        "test precondition"
    );
    assert!(
        harness
            .chain
            .block_root_at_slot(future_slot, WhenSlotSkipped::None)
            .unwrap()
            .is_none(),
        "WhenSlotSkipped::None should return None on a future slot"
    );
    assert!(
        harness
            .chain
            .block_root_at_slot(future_slot, WhenSlotSkipped::Prev)
            .unwrap()
            .is_none(),
        "WhenSlotSkipped::Prev should return None on a future slot"
    );
}
