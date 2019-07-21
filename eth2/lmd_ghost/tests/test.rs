use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness as BaseBeaconChainHarness, BlockStrategy,
};
use lmd_ghost::{LmdGhost, ThreadSafeReducedTree as BaseThreadSafeReducedTree};
use std::sync::Arc;
use store::{
    iter::{AncestorIter, BestBlockRootsIterator},
    MemoryStore, Store,
};
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, MinimalEthSpec, Slot};

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

type TestEthSpec = MinimalEthSpec;
type ThreadSafeReducedTree = BaseThreadSafeReducedTree<MemoryStore, TestEthSpec>;
type BeaconChainHarness = BaseBeaconChainHarness<ThreadSafeReducedTree, TestEthSpec>;

fn get_harness(validator_count: usize) -> BeaconChainHarness {
    let harness = BeaconChainHarness::new(validator_count);

    // Move past the zero slot.
    harness.advance_slot();

    harness
}

fn get_ancestor_roots<E: EthSpec, U: Store>(
    store: Arc<U>,
    block_root: Hash256,
) -> Vec<(Hash256, Slot)> {
    let block = store
        .get::<BeaconBlock>(&block_root)
        .expect("block should exist")
        .expect("store should not error");

    <BeaconBlock as AncestorIter<_, BestBlockRootsIterator<E, _>>>::iter_ancestor_roots(
        &block, store,
    )
    .collect()
}

fn get_slot_for_block_root(harness: &BeaconChainHarness, block_root: Hash256) -> Slot {
    harness
        .chain
        .store
        .get::<BeaconBlock>(&block_root)
        .expect("head block should exist")
        .expect("DB should not error")
        .slot
}

fn get_harness_containing_two_forks() -> (
    BeaconChainHarness,
    Vec<(Hash256, Slot)>,
    Vec<(Hash256, Slot)>,
) {
    let harness = get_harness(VALIDATOR_COUNT);

    let delay = TestEthSpec::default_spec().min_attestation_inclusion_delay as usize;

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

    (harness, honest_roots, faulty_roots)
}

#[test]
fn unnamed() {
    let (harness, honest_roots, faulty_roots) = get_harness_containing_two_forks();

    let genesis_block_root = harness.chain.genesis_block_root;
    let genesis_block = harness
        .chain
        .store
        .get::<BeaconBlock>(&genesis_block_root)
        .expect("Genesis block should exist")
        .expect("DB should not error");

    // A simple weight-calculation function where all validators have a weight of `1`.
    let weight_fn = |_validator_index| Some(1_u64);

    let new_lmd = || {
        ThreadSafeReducedTree::new(
            harness.chain.store.clone(),
            &genesis_block,
            genesis_block_root,
        )
    };

    // Create a single LMD instance and have one validator vote in reverse (highest to lowest slot)
    // down the chain.
    {
        let lmd = new_lmd();
        for (root, slot) in honest_roots.iter().rev() {
            lmd.process_attestation(0, *root, *slot)
                .expect("fork choice should accept attestations to honest roots in reverse");
        }

        // The honest head should be selected.
        let (head_root, head_slot) = honest_roots.last().unwrap();
        assert_eq!(
            lmd.find_head(*head_slot, *head_root, weight_fn),
            Ok(*head_root)
        );
    }

    // A single validator applies a single vote to each block in the honest fork, using a new tree
    // each time.
    for (root, slot) in &honest_roots {
        let lmd = new_lmd();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to honest roots");
    }

    // Same as above, but in reverse order (votes on the highest honest block first).
    for (root, slot) in honest_roots.iter().rev() {
        let lmd = new_lmd();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to honest roots in reverse");
    }

    // A single validator applies a single vote to each block in the faulty fork, using a new tree
    // each time.
    for (root, slot) in &faulty_roots {
        let lmd = new_lmd();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to faulty roots");
    }

    // Same as above, but in reverse order (votes on the highest honest block first).
    for (root, slot) in faulty_roots.iter().rev() {
        let lmd = new_lmd();
        lmd.process_attestation(0, *root, *slot)
            .expect("fork choice should accept attestations to faulty roots in reverse");
    }
}
