#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::{ExitTestTask};

pub const VALIDATOR_COUNT: usize = 10;
pub const SLOT_OFFSET: u64 = 4;
pub const EXIT_SLOT_OFFSET: u64 = 2048;

#[test]
fn valid_block_ok() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
    let (mut block, mut state) = builder.build(None, None, &spec);

    state.slot = Slot::new(133713);
    block.slot = Slot::new(424242);

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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);
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
    let builder = get_builder(&spec, SLOT_OFFSET, VALIDATOR_COUNT);

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
fn valid_insert_3_exits () {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 3;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let test_task = ExitTestTask::Valid;
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok because these are valid deposits.
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_validator_unknown() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::ValidatorUnknown;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Validator Unknwon because the exit index is incorrect
    assert_eq!(result, Err(BlockProcessingError::ExitInvalid {
        index: 0,
        reason: ExitInvalid::ValidatorUnknown(4242),
    }));
}

#[test]
fn invalid_already_exited() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::AlreadyExited;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Validator Unknwon because the exit index is incorrect
    assert_eq!(result, Err(BlockProcessingError::ExitInvalid {
        index: 0,
        reason: ExitInvalid::AlreadyExited(0),
    }));
}

#[test]
fn invalid_future_epoch() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::FutureEpoch;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Validator Unknwon because the exit index is incorrect
    assert_eq!(result, Err(BlockProcessingError::ExitInvalid {
        index: 0,
        reason: ExitInvalid::FutureEpoch { state: Epoch::from(2048 as u64), exit: spec.far_future_epoch}
    }));
}

#[test]
fn invalid_bad_signature() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::BadSignature;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Bad Signature because we signed with a different secret key than the correct one.
    assert_eq!(result, Err(BlockProcessingError::ExitInvalid {
        index: 0,
        reason: ExitInvalid::BadSignature,
    }));
}


fn get_builder(spec: &ChainSpec, slot_offset: u64, num_validators: usize) -> (BlockProcessingBuilder<MainnetEthSpec>) {

    let mut builder = BlockProcessingBuilder::new(num_validators, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + slot_offset).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}
