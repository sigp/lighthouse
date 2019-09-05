#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{
    generate_deterministic_keypairs, AttestationStrategy,
    BeaconChainHarness as BaseBeaconChainHarness, BlockStrategy,
};
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree as BaseThreadSafeReducedTree};
use rand::{prelude::*, rngs::StdRng};
use std::sync::Arc;
use store::{
    iter::{AncestorIter, BlockRootsIterator},
    MemoryStore, Store,
};
use types::{BeaconBlock, EthSpec, Hash256, MinimalEthSpec, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 3 * 8;

type TestEthSpec = MinimalEthSpec;
type ThreadSafeReducedTree = BaseThreadSafeReducedTree<MemoryStore, TestEthSpec>;
type BeaconChainHarness = BaseBeaconChainHarness<ThreadSafeReducedTree, TestEthSpec>;
type RootAndSlot = (Hash256, Slot);

lazy_static! {
    /// A lazy-static instance of a `BeaconChainHarness` that contains two forks.
    ///
    /// Reduces test setup time by providing a common harness.
    static ref FORKED_HARNESS: ForkedHarness = ForkedHarness::new();
}

/// Contains a `BeaconChainHarness` that has two forks, caused by a validator skipping a slot and
/// then some validators building on one head and some on the other.
///
/// Care should be taken to ensure that the `ForkedHarness` does not expose any interior mutability
/// from it's fields. This would cause cross-contamination between tests when used with
/// `lazy_static`.
struct ForkedHarness {
    /// Private (not `pub`) because the `BeaconChainHarness` has interior mutability. We
    /// don't expose it to avoid contamination between tests.
    harness: BeaconChainHarness,
    pub genesis_block_root: Hash256,
    pub genesis_block: BeaconBlock<TestEthSpec>,
    pub honest_head: RootAndSlot,
    pub faulty_head: RootAndSlot,
    pub honest_roots: Vec<RootAndSlot>,
    pub faulty_roots: Vec<RootAndSlot>,
}

impl ForkedHarness {
    /// A new standard instance of with constant parameters.
    pub fn new() -> Self {
        let harness = BeaconChainHarness::new(generate_deterministic_keypairs(VALIDATOR_COUNT));

        // Move past the zero slot.
        harness.advance_slot();

        let delay = TestEthSpec::default_spec().min_attestation_inclusion_delay as usize;

        let initial_blocks = delay + 5;

        // Build an initial chain where all validators agree.
        harness.extend_chain(
            initial_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );

        let two_thirds = (VALIDATOR_COUNT / 3) * 2;
        let honest_validators: Vec<usize> = (0..two_thirds).collect();
        let faulty_validators: Vec<usize> = (two_thirds..VALIDATOR_COUNT).collect();
        let honest_fork_blocks = delay + 5;
        let faulty_fork_blocks = delay + 5;

        let (honest_head, faulty_head) = harness.generate_two_forks_by_skipping_a_block(
            &honest_validators,
            &faulty_validators,
            honest_fork_blocks,
            faulty_fork_blocks,
        );

        let mut honest_roots =
            get_ancestor_roots::<TestEthSpec, _>(harness.chain.store.clone(), honest_head);

        honest_roots.insert(
            0,
            (honest_head, get_slot_for_block_root(&harness, honest_head)),
        );

        let mut faulty_roots =
            get_ancestor_roots::<TestEthSpec, _>(harness.chain.store.clone(), faulty_head);

        faulty_roots.insert(
            0,
            (faulty_head, get_slot_for_block_root(&harness, faulty_head)),
        );

        let genesis_block_root = harness.chain.genesis_block_root;
        let genesis_block = harness
            .chain
            .store
            .get::<BeaconBlock<TestEthSpec>>(&genesis_block_root)
            .expect("Genesis block should exist")
            .expect("DB should not error");

        Self {
            harness,
            genesis_block_root,
            genesis_block,
            honest_head: *honest_roots.last().expect("Chain cannot be empty"),
            faulty_head: *faulty_roots.last().expect("Chain cannot be empty"),
            honest_roots,
            faulty_roots,
        }
    }

    pub fn store_clone(&self) -> MemoryStore {
        (*self.harness.chain.store).clone()
    }

    /// Return a brand-new, empty fork choice with a reference to `harness.store`.
    pub fn new_fork_choice(&self) -> ThreadSafeReducedTree {
        // Take a full clone of the store built by the harness.
        //
        // Taking a clone here ensures that each fork choice gets it's own store so there is no
        // cross-contamination between tests.
        let store: MemoryStore = self.store_clone();

        ThreadSafeReducedTree::new(
            Arc::new(store),
            &self.genesis_block,
            self.genesis_block_root,
        )
    }

    pub fn all_block_roots(&self) -> Vec<RootAndSlot> {
        let mut all_roots = self.honest_roots.clone();
        all_roots.append(&mut self.faulty_roots.clone());

        all_roots.dedup();

        all_roots
    }

    pub fn weight_function(_validator_index: usize) -> Option<u64> {
        Some(1)
    }
}

/// Helper: returns all the ancestor roots and slots for a given block_root.
fn get_ancestor_roots<E: EthSpec, U: Store>(
    store: Arc<U>,
    block_root: Hash256,
) -> Vec<(Hash256, Slot)> {
    let block = store
        .get::<BeaconBlock<TestEthSpec>>(&block_root)
        .expect("block should exist")
        .expect("store should not error");

    <BeaconBlock<TestEthSpec> as AncestorIter<_, BlockRootsIterator<TestEthSpec, _>>>::try_iter_ancestor_roots(
        &block, store,
    )
    .expect("should be able to create ancestor iter")
    .collect()
}

/// Helper: returns the slot for some block_root.
fn get_slot_for_block_root(harness: &BeaconChainHarness, block_root: Hash256) -> Slot {
    harness
        .chain
        .store
        .get::<BeaconBlock<TestEthSpec>>(&block_root)
        .expect("head block should exist")
        .expect("DB should not error")
        .slot
}

const RANDOM_ITERATIONS: usize = 50;
const RANDOM_ACTIONS_PER_ITERATION: usize = 100;

/// Create a single LMD instance and have one validator vote in reverse (highest to lowest slot)
/// down the chain.
#[test]
fn random_scenario() {
    let harness = &FORKED_HARNESS;
    let block_roots = harness.all_block_roots();
    let validators: Vec<usize> = (0..VALIDATOR_COUNT).collect();
    let mut rng = StdRng::seed_from_u64(9375205782030385); // Keyboard mash.

    for _ in 0..RANDOM_ITERATIONS {
        let lmd = harness.new_fork_choice();

        for _ in 0..RANDOM_ACTIONS_PER_ITERATION {
            let (root, slot) = block_roots[rng.next_u64() as usize % block_roots.len()];
            let validator_index = validators[rng.next_u64() as usize % validators.len()];

            lmd.process_attestation(validator_index, root, slot)
                .expect("fork choice should accept randomly-placed attestations");

            assert_eq!(
                lmd.verify_integrity(),
                Ok(()),
                "New tree should have integrity"
            );
        }
    }
}

/// Create a single LMD instance and have one validator vote in reverse (highest to lowest slot)
/// down the chain.
#[test]
fn single_voter_persistent_instance_reverse_order() {
    let harness = &FORKED_HARNESS;

    let lmd = harness.new_fork_choice();

    assert_eq!(
        lmd.verify_integrity(),
        Ok(()),
        "New tree should have integrity"
    );

    for (root, slot) in harness.honest_roots.iter().rev() {
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to honest roots in reverse");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained whilst processing attestations"
        );
    }

    // The honest head should be selected.
    let (head_root, head_slot) = harness.honest_roots.first().unwrap();
    let (finalized_root, _) = harness.honest_roots.last().unwrap();

    assert_eq!(
        lmd.find_head(*head_slot, *finalized_root, ForkedHarness::weight_function),
        Ok(*head_root),
        "Honest head should be selected"
    );
}

/// A single validator applies a single vote to each block in the honest fork, using a new tree
/// each time.
#[test]
fn single_voter_many_instance_honest_blocks_voting_forwards() {
    let harness = &FORKED_HARNESS;

    for (root, slot) in &harness.honest_roots {
        let lmd = harness.new_fork_choice();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to honest roots");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained whilst processing attestations"
        );
    }
}

/// Same as above, but in reverse order (votes on the highest honest block first).
#[test]
fn single_voter_many_instance_honest_blocks_voting_in_reverse() {
    let harness = &FORKED_HARNESS;

    // Same as above, but in reverse order (votes on the highest honest block first).
    for (root, slot) in harness.honest_roots.iter().rev() {
        let lmd = harness.new_fork_choice();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to honest roots in reverse");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained whilst processing attestations"
        );
    }
}

/// A single validator applies a single vote to each block in the faulty fork, using a new tree
/// each time.
#[test]
fn single_voter_many_instance_faulty_blocks_voting_forwards() {
    let harness = &FORKED_HARNESS;

    for (root, slot) in &harness.faulty_roots {
        let lmd = harness.new_fork_choice();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to faulty roots");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained whilst processing attestations"
        );
    }
}

/// Same as above, but in reverse order (votes on the highest faulty block first).
#[test]
fn single_voter_many_instance_faulty_blocks_voting_in_reverse() {
    let harness = &FORKED_HARNESS;

    for (root, slot) in harness.faulty_roots.iter().rev() {
        let lmd = harness.new_fork_choice();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to faulty roots in reverse");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained whilst processing attestations"
        );
    }
}

/// Ensures that the finalized root can be set to all values in `roots`.
fn test_update_finalized_root(roots: &[(Hash256, Slot)]) {
    let harness = &FORKED_HARNESS;

    let lmd = harness.new_fork_choice();

    for (root, _slot) in roots.iter().rev() {
        let block = harness
            .store_clone()
            .get::<BeaconBlock<TestEthSpec>>(root)
            .expect("block should exist")
            .expect("db should not error");
        lmd.update_finalized_root(&block, *root)
            .expect("finalized root should update for faulty fork");

        assert_eq!(
            lmd.verify_integrity(),
            Ok(()),
            "Tree integrity should be maintained after updating the finalized root"
        );
    }
}

/// Iterates from low-to-high slot through the faulty roots, updating the finalized root.
#[test]
fn update_finalized_root_faulty() {
    let harness = &FORKED_HARNESS;

    test_update_finalized_root(&harness.faulty_roots)
}

/// Iterates from low-to-high slot through the honest roots, updating the finalized root.
#[test]
fn update_finalized_root_honest() {
    let harness = &FORKED_HARNESS;

    test_update_finalized_root(&harness.honest_roots)
}
