#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::AttestationTestTask;

pub const VALIDATOR_COUNT: usize = 100;
pub const NUM_ATTESTATIONS: u64 = 1;

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
fn valid_attestations() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttestationTestTask::Valid;
    let (block, mut state) = builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

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
fn invalid_attestation_parent_crosslink_start_epoch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttestationTestTask::BadParentCrosslinkStartEpoch;
    let (block, mut state) = builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkEndEpoch because we manually set an invalid crosslink start epoch
    assert_eq!(result, Err(BlockProcessingError::AttestationInvalid {
        index: 0,
        reason: AttestationInvalid::BadParentCrosslinkStartEpoch
    }));
}

#[test]
fn invalid_attestation_parent_crosslink_end_epoch() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttestationTestTask::BadParentCrosslinkEndEpoch;
    let (block, mut state) = builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkEndEpoch because we manually set an invalid crosslink end epoch
    assert_eq!(result, Err(BlockProcessingError::AttestationInvalid {
        index: 0,
        reason: AttestationInvalid::BadParentCrosslinkEndEpoch
    }));
}

#[test]
fn invalid_attestation_parent_crosslink_hash() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttestationTestTask::BadParentCrosslinkHash;
    let (block, mut state) = builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadParentCrosslinkHash because we manually set an invalid crosslink parent_root
    assert_eq!(result, Err(BlockProcessingError::AttestationInvalid {
        index: 0,
        reason: AttestationInvalid::BadParentCrosslinkHash
    }));

}

#[test]
fn invalid_attestation_no_committee_for_shard() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = AttestationTestTask::NoCommiteeForShard;
    let (block, mut state) = builder.build_with_n_attestations(&test_task, NUM_ATTESTATIONS, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Missing Comment
    assert_eq!(result, Err(BlockProcessingError::BeaconStateError(BeaconStateError::NoCommitteeForShard)));

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
