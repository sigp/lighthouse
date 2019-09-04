#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::AttestationProcessingOutcome;
use beacon_chain::{
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, CommonTypes, PersistedBeaconChain,
        BEACON_CHAIN_DB_KEY,
    },
    BlockProcessingOutcome,
};
use lmd_ghost::ThreadSafeReducedTree;
use rand::Rng;
use store::{MemoryStore, Store};
use types::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use types::{Deposit, EthSpec, Hash256, Keypair, MinimalEthSpec, RelativeEpoch, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type TestForkChoice = ThreadSafeReducedTree<MemoryStore, MinimalEthSpec>;

fn get_harness(validator_count: usize) -> BeaconChainHarness<TestForkChoice, MinimalEthSpec> {
    let harness = BeaconChainHarness::new(KEYPAIRS[0..validator_count].to_vec());

    harness.advance_slot();

    harness
}

#[test]
fn iterators() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        // No need to produce attestations for this test.
        AttestationStrategy::SomeValidators(vec![]),
    );

    let block_roots: Vec<(Hash256, Slot)> = harness.chain.rev_iter_block_roots().collect();
    let state_roots: Vec<(Hash256, Slot)> = harness.chain.rev_iter_state_roots().collect();

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
            x[0].1 - 1,
            "block root slots should be decreasing by one"
        )
    });
    state_roots.windows(2).for_each(|x| {
        assert_eq!(
            x[1].1,
            x[0].1 - 1,
            "state root slots should be decreasing by one"
        )
    });

    let head = &harness.chain.head();

    assert_eq!(
        *block_roots.first().expect("should have some block roots"),
        (head.beacon_block_root, head.beacon_block.slot),
        "first block root and slot should be for the head block"
    );

    assert_eq!(
        *state_roots.first().expect("should have some state roots"),
        (head.beacon_state_root, head.beacon_state.slot),
        "first state root and slot should be for the head state"
    );
}

#[test]
fn chooses_fork() {
    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let delay = MinimalEthSpec::default_spec().min_attestation_inclusion_delay as usize;

    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..VALIDATOR_COUNT).collect();

    let initial_blocks = delay + 1;
    let honest_fork_blocks = delay + 1;
    let faulty_fork_blocks = delay + 2;

    // Build an initial chain where all validators agree.
    harness.extend_chain(
        initial_blocks,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let (honest_head, faulty_head) = harness.generate_two_forks_by_skipping_a_block(
        &honest_validators,
        &faulty_validators,
        honest_fork_blocks,
        faulty_fork_blocks,
    );

    assert!(honest_head != faulty_head, "forks should be distinct");

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot,
        Slot::from(initial_blocks + honest_fork_blocks),
        "head should be at the current slot"
    );

    assert_eq!(
        harness.chain.head().beacon_block_root,
        honest_head,
        "the honest chain should be the canonical chain"
    );
}

#[test]
fn finalizes_with_full_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot, num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint.epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

#[test]
fn finalizes_with_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let attesters = (0..two_thirds).collect();

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(attesters),
    );

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot, num_blocks_produced,
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
        state.current_justified_checkpoint.epoch,
        state.current_epoch() - 2,
        "the head should be justified two behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch,
        state.current_epoch() - 4,
        "the head should be finalized three behind the current epoch"
    );
}

#[test]
fn does_not_finalize_with_less_than_two_thirds_participation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let less_than_two_thirds = two_thirds - 1;
    let attesters = (0..less_than_two_thirds).collect();

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(attesters),
    );

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot, num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint.epoch, 0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch, 0,
        "no epoch should have been finalized"
    );
}

#[test]
fn does_not_finalize_without_attestation() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(vec![]),
    );

    let state = &harness.chain.head().beacon_state;

    assert_eq!(
        state.slot, num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint.epoch, 0,
        "no epoch should have been justified"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch, 0,
        "no epoch should have been finalized"
    );
}

#[test]
fn roundtrip_operation_pool() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    // Add some attestations
    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );
    assert!(harness.chain.op_pool.num_attestations() > 0);

    // Add some deposits
    let rng = &mut XorShiftRng::from_seed([66; 16]);
    for i in 0..rng.gen_range(1, VALIDATOR_COUNT) {
        harness
            .chain
            .process_deposit(i as u64, Deposit::random_for_test(rng))
            .unwrap();
    }

    // TODO: could add some other operations
    harness.chain.persist().unwrap();

    let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
    let p: PersistedBeaconChain<CommonTypes<TestForkChoice, MinimalEthSpec>> =
        harness.chain.store.get(&key).unwrap().unwrap();

    let restored_op_pool = p
        .op_pool
        .into_operation_pool(&p.canonical_head.beacon_state, &harness.spec);

    assert_eq!(harness.chain.op_pool, restored_op_pool);
}

#[test]
fn free_attestations_added_to_fork_choice_some_none() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() / 2;

    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &harness.chain.head().beacon_state;
    let fork_choice = &harness.chain.fork_choice;

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
                slot,
                "Latest message slot for {} should be equal to slot {}.",
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

#[test]
fn attestations_with_increasing_slots() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 5;

    let harness = get_harness(VALIDATOR_COUNT);

    let mut attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness.extend_chain(
            2,
            BlockStrategy::OnCanonicalHead,
            // Don't produce & include any attestations (we'll collect them later).
            AttestationStrategy::SomeValidators(vec![]),
        );

        attestations.append(&mut harness.get_free_attestations(
            &AttestationStrategy::AllValidators,
            &harness.chain.head().beacon_state,
            harness.chain.head().beacon_block_root,
            harness.chain.head().beacon_block.slot,
        ));

        harness.advance_slot();
    }

    for attestation in attestations {
        assert_eq!(
            harness.chain.process_attestation(attestation),
            Ok(AttestationProcessingOutcome::Processed)
        )
    }
}

#[test]
fn free_attestations_added_to_fork_choice_all_updated() {
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 2 - 1;

    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &harness.chain.head().beacon_state;
    let fork_choice = &harness.chain.fork_choice;

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
            slot,
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

fn run_skip_slot_test(skip_slots: u64) {
    let num_validators = 8;
    let harness_a = get_harness(num_validators);
    let harness_b = get_harness(num_validators);

    for _ in 0..skip_slots {
        harness_a.advance_slot();
        harness_b.advance_slot();
    }

    harness_a.extend_chain(
        1,
        BlockStrategy::OnCanonicalHead,
        // No attestation required for test.
        AttestationStrategy::SomeValidators(vec![]),
    );

    assert_eq!(
        harness_a.chain.head().beacon_block.slot,
        Slot::new(skip_slots + 1)
    );
    assert_eq!(harness_b.chain.head().beacon_block.slot, Slot::new(0));

    assert_eq!(
        harness_b
            .chain
            .process_block(harness_a.chain.head().beacon_block.clone()),
        Ok(BlockProcessingOutcome::Processed {
            block_root: harness_a.chain.head().beacon_block_root
        })
    );

    assert_eq!(
        harness_b.chain.head().beacon_block.slot,
        Slot::new(skip_slots + 1)
    );
}

#[test]
fn produces_and_processes_with_genesis_skip_slots() {
    for i in 0..MinimalEthSpec::slots_per_epoch() * 4 {
        run_skip_slot_test(i)
    }
}
