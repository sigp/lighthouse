use beacon_chain::test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy};
use lmd_ghost::ThreadSafeReducedTree;
use std::sync::Arc;
use store::{
    iter::{AncestorIter, BestBlockRootsIterator},
    MemoryStore, Store,
};
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, MinimalEthSpec, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

type TestForkChoice = ThreadSafeReducedTree<MemoryStore, MinimalEthSpec>;

fn get_harness(validator_count: usize) -> BeaconChainHarness<TestForkChoice, MinimalEthSpec> {
    let harness = BeaconChainHarness::new(validator_count);

    // Move past the zero slot.
    harness.advance_slot();

    harness
}

fn get_ancestor_roots<E: EthSpec, U: Store>(store: Arc<U>, block_root: Hash256) -> Vec<Hash256> {
    let block = store
        .get::<BeaconBlock>(&block_root)
        .expect("block should exist")
        .expect("store should not error");

    <BeaconBlock as AncestorIter<_, BestBlockRootsIterator<E, _>>>::iter_ancestor_roots(
        &block, store,
    )
    .map(|(root, _slot)| root)
    .collect()
}

#[test]
fn chooses_fork() {
    let harness = get_harness(VALIDATOR_COUNT);

    let delay = MinimalEthSpec::default_spec().min_attestation_inclusion_delay as usize;

    let initial_blocks = delay + 1;

    // Build an initial chain where all validators agree.
    harness.extend_chain(
        initial_blocks,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..VALIDATOR_COUNT).collect();
    let honest_fork_blocks = delay + 3;
    let faulty_fork_blocks = delay + 3;

    let (honest_head, faulty_head) = harness.generate_two_forks_by_skipping_a_block(
        &honest_validators,
        &faulty_validators,
        honest_fork_blocks,
        faulty_fork_blocks,
    );

    let state = &harness.chain.head().beacon_state;

    let mut honest_roots =
        get_ancestor_roots::<MinimalEthSpec, _>(harness.chain.store.clone(), honest_head);
    honest_roots.push(honest_head);
    let mut faulty_roots =
        get_ancestor_roots::<MinimalEthSpec, _>(harness.chain.store.clone(), faulty_head);
    faulty_roots.push(faulty_head);

    dbg!(honest_roots);
    dbg!(faulty_roots);

    panic!();
}
