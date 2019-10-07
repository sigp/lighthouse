#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::test_utils::ProposerSlashingTestTask;
use types::*;

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let (block, mut state) = builder.build(None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_block_header_state_slot() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(None, None, &spec);

    state.slot = Slot::new(133_713);
    block.slot = Slot::new(424_242);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::StateSlotMismatch
        })
    );
}

#[test]
fn invalid_parent_block_root() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let invalid_parent_root = Hash256::from([0xAA; 32]);
    let (block, mut state) = builder.build(None, Some(invalid_parent_root), &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ParentBlockRootMismatch {
                state: Hash256::from_slice(&state.latest_block_header.signed_root()),
                block: block.parent_root
            }
        })
    );
}

#[test]
fn invalid_block_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(None, None, &spec);

    // sign the block with a keypair that is not the expected proposer
    let keypair = Keypair::random();
    let message = block.signed_root();
    let epoch = block.slot.epoch(MainnetEthSpec::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::BeaconProposer, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);

    // process block with invalid block signature
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // should get a BadSignature error
    assert_eq!(
        result,
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ProposalSignatureInvalid
        })
    );
}

#[test]
fn invalid_randao_reveal_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);

    // sign randao reveal with random keypair
    let keypair = Keypair::random();
    let (block, mut state) = builder.build(Some(keypair.sk), None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // should get a BadRandaoSignature error
    assert_eq!(result, Err(BlockProcessingError::RandaoSignatureInvalid));
}

#[test]
fn valid_insert_proposer_slashing() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::Valid;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) because we inserted a valid proposer slashing
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_proposer_slashing_proposals_identical() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::ProposalsIdentical;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ProposalsIdentical because we the two headers are identical
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposalsIdentical
        })
    );
}

#[test]
fn invalid_proposer_slashing_proposer_unknown() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::ProposerUnknown;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ProposerUnknown because validator_index is unknown
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposerUnknown(3_141_592)
        })
    );
}

#[test]
fn invalid_proposer_slashing_proposal_epoch_mismatch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::ProposalEpochMismatch;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting ProposalEpochMismatch because the two epochs are different
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::ProposalEpochMismatch(
                Slot::from(0 as u64),
                Slot::from(128 as u64)
            )
        })
    );
}

#[test]
fn invalid_bad_proposal_1_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::BadProposal1Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadProposal1Signature because signature of proposal 1 is invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::BadProposal1Signature
        })
    );
}

#[test]
fn invalid_bad_proposal_2_signature() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = ProposerSlashingTestTask::BadProposal2Signature;
    let (block, mut state) = builder.build_with_proposer_slashing(&test_task, 1, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadProposal2Signature because signature of proposal 2 is invalid
    assert_eq!(
        result,
        Err(BlockProcessingError::ProposerSlashingInvalid {
            index: 0,
            reason: ProposerSlashingInvalid::BadProposal2Signature
        })
    );
}

fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder<MainnetEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + 4).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}
