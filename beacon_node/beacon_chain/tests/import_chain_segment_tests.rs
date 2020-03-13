// #![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    BlockError,
};
use types::{Hash256, Keypair, MainnetEthSpec, SignedBeaconBlock, Slot};

type E = MainnetEthSpec;

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;
pub const CHAIN_SEGMENT_LENGTH: usize = 64 * 5;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);

    /// A cached set of valid blocks
    static ref CHAIN_SEGMENT: Vec<SignedBeaconBlock<E>> = get_chain_segment();
}

fn get_chain_segment() -> Vec<SignedBeaconBlock<E>> {
    let harness = get_harness(VALIDATOR_COUNT);

    harness.extend_chain(
        CHAIN_SEGMENT_LENGTH,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    harness
        .chain
        .chain_dump()
        .expect("should dump chain")
        .into_iter()
        .skip(1)
        .map(|snapshot| snapshot.beacon_block)
        .collect()
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<E>> {
    let harness = BeaconChainHarness::new(MainnetEthSpec, KEYPAIRS[0..validator_count].to_vec());

    harness.advance_slot();

    harness
}

#[test]
fn chain_segement_full_segment() {
    let harness = get_harness(VALIDATOR_COUNT);
    let blocks = CHAIN_SEGMENT.clone();

    harness
        .chain
        .slot_clock
        .set_slot(blocks.last().unwrap().slot().as_u64());

    harness
        .chain
        .import_chain_segment(blocks.clone())
        .expect("should import chain segment");

    harness.chain.fork_choice().expect("should run fork choice");

    assert_eq!(
        harness
            .chain
            .head_info()
            .expect("should get harness b head")
            .block_root,
        blocks.last().unwrap().canonical_root(),
        "harness should have last block as head"
    );
}

#[test]
fn chain_segement_varying_chunk_size() {
    for chunk_size in &[1, 2, 3, 5, 31, 32, 33, 42] {
        let harness = get_harness(VALIDATOR_COUNT);
        let blocks = CHAIN_SEGMENT.clone();

        harness
            .chain
            .slot_clock
            .set_slot(blocks.last().unwrap().slot().as_u64());

        for chunk in blocks.chunks(*chunk_size) {
            harness
                .chain
                .import_chain_segment(chunk.to_vec())
                .expect(&format!(
                    "should import chain segment of len {}",
                    chunk_size
                ));
        }

        harness.chain.fork_choice().expect("should run fork choice");

        assert_eq!(
            harness
                .chain
                .head_info()
                .expect("should get harness b head")
                .block_root,
            blocks.last().unwrap().canonical_root(),
            "harness should have last block as head"
        );
    }
}

#[test]
fn chain_segement_non_linear_parent_roots() {
    let harness = get_harness(VALIDATOR_COUNT);

    /*
     * Test with a block removed.
     */
    let mut blocks = CHAIN_SEGMENT.clone();
    blocks.remove(2);

    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().slot().as_u64());

    assert_eq!(
        harness.chain.import_chain_segment(blocks.clone()),
        Err(BlockError::NonLinearParentRoots),
        "should not import chain with missing parent"
    );

    /*
     * Test with a modified parent root.
     */
    let mut blocks = CHAIN_SEGMENT.clone();
    blocks[3].message.parent_root = Hash256::zero();

    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().slot().as_u64());

    assert_eq!(
        harness.chain.import_chain_segment(blocks.clone()),
        Err(BlockError::NonLinearParentRoots),
        "should not import chain with a broken parent root link"
    );
}

#[test]
fn chain_segement_non_linear_slots() {
    let harness = get_harness(VALIDATOR_COUNT);

    /*
     * Test where a child is lower than the parent.
     */

    let mut blocks = CHAIN_SEGMENT.clone();
    blocks[3].message.slot = Slot::new(0);

    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().slot().as_u64());

    assert_eq!(
        harness.chain.import_chain_segment(blocks.clone()),
        Err(BlockError::NonLinearSlots),
        "should not import chain with a parent that has a lower slot than its child"
    );

    /*
     * Test where a child is equal to the parent.
     */

    let mut blocks = CHAIN_SEGMENT.clone();
    blocks[3].message.slot = blocks[2].message.slot;

    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().slot().as_u64());

    assert_eq!(
        harness.chain.import_chain_segment(blocks.clone()),
        Err(BlockError::NonLinearSlots),
        "should not import chain with a parent that has an equal slot to its child"
    );
}
