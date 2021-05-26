#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconSnapshot, BlockError,
};
use slasher::{Config as SlasherConfig, Slasher};
use std::sync::Arc;
use store::config::StoreConfig;
use tempfile::tempdir;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, AttestationData,
    AttesterSlashing, Checkpoint, Deposit, DepositData, Epoch, EthSpec, Hash256,
    IndexedAttestation, Keypair, MainnetEthSpec, ProposerSlashing, Signature, SignedBeaconBlock,
    SignedBeaconBlockHeader, SignedVoluntaryExit, Slot, VoluntaryExit, DEPOSIT_TREE_DEPTH,
};

type E = MainnetEthSpec;

// Should ideally be divisible by 3.
const VALIDATOR_COUNT: usize = 24;
const CHAIN_SEGMENT_LENGTH: usize = 64 * 5;
const BLOCK_INDICES: &[usize] = &[0, 1, 32, 64, 68 + 1, 129, CHAIN_SEGMENT_LENGTH - 1];

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);

    /// A cached set of valid blocks
    static ref CHAIN_SEGMENT: Vec<BeaconSnapshot<E>> = get_chain_segment();
}

fn get_chain_segment() -> Vec<BeaconSnapshot<E>> {
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
        .collect()
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::new_with_store_config(
        MainnetEthSpec,
        KEYPAIRS[0..validator_count].to_vec(),
        StoreConfig::default(),
    );

    harness.advance_slot();

    harness
}

fn chain_segment_blocks() -> Vec<SignedBeaconBlock<E>> {
    CHAIN_SEGMENT
        .iter()
        .map(|snapshot| snapshot.beacon_block.clone())
        .collect()
}

fn junk_signature() -> Signature {
    let kp = generate_deterministic_keypair(VALIDATOR_COUNT);
    let message = Hash256::from_slice(&[42; 32]);
    kp.sk.sign(message)
}

fn junk_aggregate_signature() -> AggregateSignature {
    let mut agg_sig = AggregateSignature::empty();
    agg_sig.add_assign(&junk_signature());
    agg_sig
}

fn update_proposal_signatures(
    snapshots: &mut [BeaconSnapshot<E>],
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
) {
    for snapshot in snapshots {
        let spec = &harness.chain.spec;
        let slot = snapshot.beacon_block.slot();
        let state = &snapshot.beacon_state;
        let proposer_index = state
            .get_beacon_proposer_index(slot, spec)
            .expect("should find proposer index");
        let keypair = harness
            .validator_keypairs
            .get(proposer_index)
            .expect("proposer keypair should be available");

        snapshot.beacon_block = snapshot.beacon_block.message.clone().sign(
            &keypair.sk,
            &state.fork,
            state.genesis_validators_root,
            spec,
        );
    }
}

fn update_parent_roots(snapshots: &mut [BeaconSnapshot<E>]) {
    for i in 0..snapshots.len() {
        let root = snapshots[i].beacon_block.canonical_root();
        if let Some(child) = snapshots.get_mut(i + 1) {
            child.beacon_block.message.parent_root = root
        }
    }
}

#[test]
fn chain_segment_full_segment() {
    let harness = get_harness(VALIDATOR_COUNT);
    let blocks = chain_segment_blocks();

    harness
        .chain
        .slot_clock
        .set_slot(blocks.last().unwrap().slot().as_u64());

    // Sneak in a little check to ensure we can process empty chain segments.
    harness
        .chain
        .process_chain_segment(vec![])
        .into_block_error()
        .expect("should import empty chain segment");

    harness
        .chain
        .process_chain_segment(blocks.clone())
        .into_block_error()
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
fn chain_segment_varying_chunk_size() {
    for chunk_size in &[1, 2, 3, 5, 31, 32, 33, 42] {
        let harness = get_harness(VALIDATOR_COUNT);
        let blocks = chain_segment_blocks();

        harness
            .chain
            .slot_clock
            .set_slot(blocks.last().unwrap().slot().as_u64());

        for chunk in blocks.chunks(*chunk_size) {
            harness
                .chain
                .process_chain_segment(chunk.to_vec())
                .into_block_error()
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
fn chain_segment_non_linear_parent_roots() {
    let harness = get_harness(VALIDATOR_COUNT);
    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().beacon_block.slot().as_u64());

    /*
     * Test with a block removed.
     */
    let mut blocks = chain_segment_blocks();
    blocks.remove(2);

    assert!(
        matches!(
            harness
                .chain
                .process_chain_segment(blocks.clone())
                .into_block_error(),
            Err(BlockError::NonLinearParentRoots)
        ),
        "should not import chain with missing parent"
    );

    /*
     * Test with a modified parent root.
     */
    let mut blocks = chain_segment_blocks();
    blocks[3].message.parent_root = Hash256::zero();

    assert!(
        matches!(
            harness
                .chain
                .process_chain_segment(blocks.clone())
                .into_block_error(),
            Err(BlockError::NonLinearParentRoots)
        ),
        "should not import chain with a broken parent root link"
    );
}

#[test]
fn chain_segment_non_linear_slots() {
    let harness = get_harness(VALIDATOR_COUNT);
    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().beacon_block.slot().as_u64());

    /*
     * Test where a child is lower than the parent.
     */

    let mut blocks = chain_segment_blocks();
    blocks[3].message.slot = Slot::new(0);

    assert!(
        matches!(
            harness
                .chain
                .process_chain_segment(blocks.clone())
                .into_block_error(),
            Err(BlockError::NonLinearSlots)
        ),
        "should not import chain with a parent that has a lower slot than its child"
    );

    /*
     * Test where a child is equal to the parent.
     */

    let mut blocks = chain_segment_blocks();
    blocks[3].message.slot = blocks[2].message.slot;

    assert!(
        matches!(
            harness
                .chain
                .process_chain_segment(blocks.clone())
                .into_block_error(),
            Err(BlockError::NonLinearSlots)
        ),
        "should not import chain with a parent that has an equal slot to its child"
    );
}

fn assert_invalid_signature(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    block_index: usize,
    snapshots: &[BeaconSnapshot<E>],
    item: &str,
) {
    let blocks = snapshots
        .iter()
        .map(|snapshot| snapshot.beacon_block.clone())
        .collect();

    // Ensure the block will be rejected if imported in a chain segment.
    assert!(
        matches!(
            harness
                .chain
                .process_chain_segment(blocks)
                .into_block_error(),
            Err(BlockError::InvalidSignature)
        ),
        "should not import chain segment with an invalid {} signature",
        item
    );

    // Ensure the block will be rejected if imported on its own (without gossip checking).
    let ancestor_blocks = CHAIN_SEGMENT
        .iter()
        .take(block_index)
        .map(|snapshot| snapshot.beacon_block.clone())
        .collect();
    // We don't care if this fails, we just call this to ensure that all prior blocks have been
    // imported prior to this test.
    let _ = harness.chain.process_chain_segment(ancestor_blocks);
    assert!(
        matches!(
            harness
                .chain
                .process_block(snapshots[block_index].beacon_block.clone()),
            Err(BlockError::InvalidSignature)
        ),
        "should not import individual block with an invalid {} signature",
        item
    );

    // NOTE: we choose not to check gossip verification here. It only checks one signature
    // (proposal) and that is already tested elsewhere in this file.
    //
    // It's not trivial to just check gossip verification since it will start refusing
    // blocks as soon as it has seen one valid proposal signature for a given (validator,
    // slot) tuple.
}

fn get_invalid_sigs_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = get_harness(VALIDATOR_COUNT);
    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT.last().unwrap().beacon_block.slot().as_u64());
    harness
}
#[test]
fn invalid_signature_gossip_block() {
    for &block_index in BLOCK_INDICES {
        // Ensure the block will be rejected if imported on its own (without gossip checking).
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        snapshots[block_index].beacon_block.signature = junk_signature();
        // Import all the ancestors before the `block_index` block.
        let ancestor_blocks = CHAIN_SEGMENT
            .iter()
            .take(block_index)
            .map(|snapshot| snapshot.beacon_block.clone())
            .collect();
        harness
            .chain
            .process_chain_segment(ancestor_blocks)
            .into_block_error()
            .expect("should import all blocks prior to the one being tested");
        assert!(
            matches!(
                harness
                    .chain
                    .process_block(snapshots[block_index].beacon_block.clone()),
                Err(BlockError::InvalidSignature)
            ),
            "should not import individual block with an invalid gossip signature",
        );
    }
}

#[test]
fn invalid_signature_block_proposal() {
    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        snapshots[block_index].beacon_block.signature = junk_signature();
        let blocks = snapshots
            .iter()
            .map(|snapshot| snapshot.beacon_block.clone())
            .collect::<Vec<_>>();
        // Ensure the block will be rejected if imported in a chain segment.
        assert!(
            matches!(
                harness
                    .chain
                    .process_chain_segment(blocks)
                    .into_block_error(),
                Err(BlockError::InvalidSignature)
            ),
            "should not import chain segment with an invalid block signature",
        );
    }
}

#[test]
fn invalid_signature_randao_reveal() {
    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        snapshots[block_index]
            .beacon_block
            .message
            .body
            .randao_reveal = junk_signature();
        update_parent_roots(&mut snapshots);
        update_proposal_signatures(&mut snapshots, &harness);
        assert_invalid_signature(&harness, block_index, &snapshots, "randao");
    }
}

#[test]
fn invalid_signature_proposer_slashing() {
    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        let proposer_slashing = ProposerSlashing {
            signed_header_1: SignedBeaconBlockHeader {
                message: snapshots[block_index].beacon_block.message.block_header(),
                signature: junk_signature(),
            },
            signed_header_2: SignedBeaconBlockHeader {
                message: snapshots[block_index].beacon_block.message.block_header(),
                signature: junk_signature(),
            },
        };
        snapshots[block_index]
            .beacon_block
            .message
            .body
            .proposer_slashings
            .push(proposer_slashing)
            .expect("should update proposer slashing");
        update_parent_roots(&mut snapshots);
        update_proposal_signatures(&mut snapshots, &harness);
        assert_invalid_signature(&harness, block_index, &snapshots, "proposer slashing");
    }
}

#[test]
fn invalid_signature_attester_slashing() {
    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        let indexed_attestation = IndexedAttestation {
            attesting_indices: vec![0].into(),
            data: AttestationData {
                slot: Slot::new(0),
                index: 0,
                beacon_block_root: Hash256::zero(),
                source: Checkpoint {
                    epoch: Epoch::new(0),
                    root: Hash256::zero(),
                },
                target: Checkpoint {
                    epoch: Epoch::new(0),
                    root: Hash256::zero(),
                },
            },
            signature: junk_aggregate_signature(),
        };
        let attester_slashing = AttesterSlashing {
            attestation_1: indexed_attestation.clone(),
            attestation_2: indexed_attestation,
        };
        snapshots[block_index]
            .beacon_block
            .message
            .body
            .attester_slashings
            .push(attester_slashing)
            .expect("should update attester slashing");
        update_parent_roots(&mut snapshots);
        update_proposal_signatures(&mut snapshots, &harness);
        assert_invalid_signature(&harness, block_index, &snapshots, "attester slashing");
    }
}

#[test]
fn invalid_signature_attestation() {
    let mut checked_attestation = false;

    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        if let Some(attestation) = snapshots[block_index]
            .beacon_block
            .message
            .body
            .attestations
            .get_mut(0)
        {
            attestation.signature = junk_aggregate_signature();
            update_parent_roots(&mut snapshots);
            update_proposal_signatures(&mut snapshots, &harness);
            assert_invalid_signature(&harness, block_index, &snapshots, "attestation");
            checked_attestation = true;
        }
    }

    assert!(
        checked_attestation,
        "the test should check an attestation signature"
    )
}

#[test]
fn invalid_signature_deposit() {
    for &block_index in BLOCK_INDICES {
        // Note: an invalid deposit signature is permitted!
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        let deposit = Deposit {
            proof: vec![Hash256::zero(); DEPOSIT_TREE_DEPTH + 1].into(),
            data: DepositData {
                pubkey: Keypair::random().pk.into(),
                withdrawal_credentials: Hash256::zero(),
                amount: 0,
                signature: junk_signature().into(),
            },
        };
        snapshots[block_index]
            .beacon_block
            .message
            .body
            .deposits
            .push(deposit)
            .expect("should update deposit");
        update_parent_roots(&mut snapshots);
        update_proposal_signatures(&mut snapshots, &harness);
        let blocks = snapshots
            .iter()
            .map(|snapshot| snapshot.beacon_block.clone())
            .collect();
        assert!(
            !matches!(
                harness
                    .chain
                    .process_chain_segment(blocks)
                    .into_block_error(),
                Err(BlockError::InvalidSignature)
            ),
            "should not throw an invalid signature error for a bad deposit signature"
        );
    }
}

#[test]
fn invalid_signature_exit() {
    for &block_index in BLOCK_INDICES {
        let harness = get_invalid_sigs_harness();
        let mut snapshots = CHAIN_SEGMENT.clone();
        let epoch = snapshots[block_index].beacon_state.current_epoch();
        snapshots[block_index]
            .beacon_block
            .message
            .body
            .voluntary_exits
            .push(SignedVoluntaryExit {
                message: VoluntaryExit {
                    epoch,
                    validator_index: 0,
                },
                signature: junk_signature(),
            })
            .expect("should update deposit");
        update_parent_roots(&mut snapshots);
        update_proposal_signatures(&mut snapshots, &harness);
        assert_invalid_signature(&harness, block_index, &snapshots, "voluntary exit");
    }
}

fn unwrap_err<T, E>(result: Result<T, E>) -> E {
    match result {
        Ok(_) => panic!("called unwrap_err on Ok"),
        Err(e) => e,
    }
}

#[test]
fn block_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);

    let block_index = CHAIN_SEGMENT_LENGTH - 2;

    harness
        .chain
        .slot_clock
        .set_slot(CHAIN_SEGMENT[block_index].beacon_block.slot().as_u64());

    // Import the ancestors prior to the block we're testing.
    for snapshot in &CHAIN_SEGMENT[0..block_index] {
        let gossip_verified = harness
            .chain
            .verify_block_for_gossip(snapshot.beacon_block.clone())
            .expect("should obtain gossip verified block");

        harness
            .chain
            .process_block(gossip_verified)
            .expect("should import valid gossip verified block");
    }

    /*
     * This test ensures that:
     *
     * Spec v0.12.1
     *
     * The block is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) --
     * i.e. validate that signed_beacon_block.message.slot <= current_slot (a client MAY queue
     * future blocks for processing at the appropriate slot).
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    let expected_block_slot = block.message.slot + 1;
    block.message.slot = expected_block_slot;
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block)),
            BlockError::FutureSlot {
                present_slot,
                block_slot,
            }
            if present_slot == expected_block_slot - 1 && block_slot == expected_block_slot
        ),
        "should not import a block with a future slot"
    );

    /*
     * This test ensure that:
     *
     * Spec v0.12.1
     *
     * The block is from a slot greater than the latest finalized slot -- i.e. validate that
     * signed_beacon_block.message.slot >
     * compute_start_slot_at_epoch(state.finalized_checkpoint.epoch) (a client MAY choose to
     * validate and store such blocks for additional purposes -- e.g. slashing detection, archive
     * nodes, etc).
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    let expected_finalized_slot = harness
        .chain
        .head_info()
        .expect("should get head info")
        .finalized_checkpoint
        .epoch
        .start_slot(E::slots_per_epoch());
    block.message.slot = expected_finalized_slot;
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block)),
            BlockError::WouldRevertFinalizedSlot {
                block_slot,
                finalized_slot,
            }
            if block_slot == expected_finalized_slot && finalized_slot == expected_finalized_slot
        ),
        "should not import a block with a finalized slot"
    );

    /*
     * This test ensures that:
     *
     * Spec v0.12.1
     *
     * The proposer signature, signed_beacon_block.signature, is valid with respect to the
     * proposer_index pubkey.
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    block.signature = junk_signature();
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block)),
            BlockError::ProposalSignatureInvalid
        ),
        "should not import a block with an invalid proposal signature"
    );

    /*
     * This test ensures that:
     *
     * Spec v0.12.2
     *
     * The block's parent (defined by block.parent_root) passes validation.
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    let parent_root = Hash256::from_low_u64_be(42);
    block.message.parent_root = parent_root;
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block)),
            BlockError::ParentUnknown(block)
            if block.parent_root() == parent_root
        ),
        "should not import a block for an unknown parent"
    );

    /*
     * This test ensures that:
     *
     * Spec v0.12.2
     *
     * The current finalized_checkpoint is an ancestor of block -- i.e. get_ancestor(store,
     * block.parent_root, compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)) ==
     * store.finalized_checkpoint.root
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    let parent_root = CHAIN_SEGMENT[0].beacon_block_root;
    block.message.parent_root = parent_root;
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block)),
            BlockError::NotFinalizedDescendant { block_parent_root }
            if block_parent_root == parent_root
        ),
        "should not import a block that conflicts with finality"
    );

    /*
     * This test ensures that:
     *
     * Spec v0.12.1
     *
     * The block is proposed by the expected proposer_index for the block's slot in the context of
     * the current shuffling (defined by parent_root/slot). If the proposer_index cannot
     * immediately be verified against the expected shuffling, the block MAY be queued for later
     * processing while proposers for the block's branch are calculated.
     */

    let mut block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    let expected_proposer = block.message.proposer_index;
    let other_proposer = (0..VALIDATOR_COUNT as u64)
        .into_iter()
        .find(|i| *i != block.message.proposer_index)
        .expect("there must be more than one validator in this test");
    block.message.proposer_index = other_proposer;
    let block = block.message.clone().sign(
        &generate_deterministic_keypair(other_proposer as usize).sk,
        &harness.chain.head_info().unwrap().fork,
        harness.chain.genesis_validators_root,
        &harness.chain.spec,
    );
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block.clone())),
            BlockError::IncorrectBlockProposer {
                block,
                local_shuffling,
            }
            if block == other_proposer && local_shuffling == expected_proposer
        ),
        "should not import a block with the wrong proposer index"
    );
    // Check to ensure that we registered this is a valid block from this proposer.
    assert!(
        matches!(
            unwrap_err(harness.chain.verify_block_for_gossip(block.clone())),
            BlockError::RepeatProposal {
                proposer,
                slot,
            }
            if proposer == other_proposer && slot == block.message.slot
        ),
        "should register any valid signature against the proposer, even if the block failed later verification"
    );

    let block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    assert!(
        harness.chain.verify_block_for_gossip(block).is_ok(),
        "the valid block should be processed"
    );

    /*
     * This test ensures that:
     *
     * Spec v0.12.1
     *
     * The block is the first block with valid signature received for the proposer for the slot,
     * signed_beacon_block.message.slot.
     */

    let block = CHAIN_SEGMENT[block_index].beacon_block.clone();
    assert!(
        matches!(
            harness
                .chain
                .verify_block_for_gossip(block.clone())
                .err()
                .expect("should error when processing known block"),
            BlockError::RepeatProposal {
                proposer,
                slot,
            }
            if proposer == block.message.proposer_index && slot == block.message.slot
        ),
        "the second proposal by this validator should be rejected"
    );
}

#[test]
fn verify_block_for_gossip_slashing_detection() {
    let mut harness = get_harness(VALIDATOR_COUNT);

    let slasher_dir = tempdir().unwrap();
    let slasher = Arc::new(
        Slasher::open(
            SlasherConfig::new(slasher_dir.path().into()).for_testing(),
            harness.logger().clone(),
        )
        .unwrap(),
    );
    harness.chain.slasher = Some(slasher.clone());

    let state = harness.get_current_state();
    let (block1, _) = harness.make_block(state.clone(), Slot::new(1));
    let (block2, _) = harness.make_block(state, Slot::new(1));

    let verified_block = harness.chain.verify_block_for_gossip(block1).unwrap();
    harness.chain.process_block(verified_block).unwrap();
    unwrap_err(harness.chain.verify_block_for_gossip(block2));

    // Slasher should have been handed the two conflicting blocks and crafted a slashing.
    slasher.process_queued(Epoch::new(0)).unwrap();
    let proposer_slashings = slasher.get_proposer_slashings();
    assert_eq!(proposer_slashings.len(), 1);
    // windows won't delete the temporary directory if you don't do this..
    drop(harness);
    drop(slasher);
    slasher_dir.close().unwrap();
}
