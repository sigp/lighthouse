#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::test_utils::{DepositTestTask, ExitTestTask};
use types::*;

pub const NUM_DEPOSITS: u64 = 1;
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
fn valid_4_deposits() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(4, test_task, None, None, &spec);

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
fn valid_insert_max_deposits_plus_one() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;
    let num_deposits = <MainnetEthSpec as EthSpec>::MaxDeposits::to_u64() + 1;

    let (block, mut state) =
        builder.build_with_n_deposits(num_deposits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Should return ok because actual size of deposits vector should be MaxDeposits.
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_deposit_count_too_big() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let big_deposit_count = NUM_DEPOSITS + 1;
    state.eth1_data.deposit_count = big_deposit_count;

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting DepositCountInvalid because we incremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: big_deposit_count as usize,
            found: 1
        })
    );
}

#[test]
fn invalid_deposit_count_too_small() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let small_deposit_count = NUM_DEPOSITS - 1;
    state.eth1_data.deposit_count = small_deposit_count;
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting DepositCountInvalid because we decremented the deposit_count
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositCountInvalid {
            expected: small_deposit_count as usize,
            found: 1
        })
    );
}

#[test]
fn invalid_deposit_bad_merkle_proof() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let bad_index = state.eth1_deposit_index as usize;

    // Manually offsetting deposit count and index to trigger bad merkle proof
    state.eth1_data.deposit_count += 1;
    state.eth1_deposit_index += 1;
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadMerkleProof because the proofs were created with different indices
    assert_eq!(
        result,
        Err(BlockProcessingError::DepositInvalid {
            index: bad_index,
            reason: DepositInvalid::BadMerkleProof
        })
    );
}

#[test]
fn invalid_deposit_wrong_pubkey() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::BadPubKey;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though the public key provided does not correspond to the correct public key
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_wrong_sig() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::BadSig;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though the block signature does not correspond to the correct public key
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_deposit_invalid_pub_key() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec, EXIT_SLOT_OFFSET, VALIDATOR_COUNT);
    let test_task = DepositTestTask::InvalidPubKey;

    let (block, mut state) =
        builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting Ok(()) even though we passed in invalid publickeybytes in the public key field of the deposit data.
    assert_eq!(result, Ok(()));
}

#[test]
fn valid_insert_3_exits() {
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

    // Expecting Ok because these are valid exits.
    assert_eq!(result, Ok(()));
}

#[test]
fn valid_insert_max_exits_plus_one() {
    let spec = MainnetEthSpec::default_spec();
    let num_exits = <MainnetEthSpec as EthSpec>::MaxVoluntaryExits::to_u64() as usize + 1;
    let num_validators = num_exits + 1;
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

    // Expecting Ok because these are valid deposits, and the vector
    // containing exits shouldn't be bigger than MaxVoluntaryExits.
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_exit_validator_unknown() {
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
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::ValidatorUnknown(4242),
        })
    );
}

#[test]
fn invalid_exit_already_exited() {
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

    // Expecting AlreadyExited because we manually set the exit_epoch to be different than far_future_epoch.
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::AlreadyExited(0),
        })
    );
}

#[test]
fn invalid_exit_not_active() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::NotActive;
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

    // Expecting NotActive because we manually set the activation_epoch to be in the future
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::NotActive(0),
        })
    );
}

#[test]
fn invalid_exit_already_initiated() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::AlreadyInitiated;
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

    // Expecting Ok(()) even though we inserted the same exit twice
    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_exit_future_epoch() {
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

    // Expecting FutureEpoch because we set the exit_epoch to be far_future_epoch
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::FutureEpoch {
                state: Epoch::from(2048 as u64),
                exit: spec.far_future_epoch
            }
        })
    );
}

#[test]
fn invalid_exit_too_young() {
    use std::cmp::max;

    let spec = MainnetEthSpec::default_spec();
    let num_exits = 1;
    let test_task = ExitTestTask::Valid;
    let num_validators = max(VALIDATOR_COUNT, num_exits);
    let builder = get_builder(&spec, SLOT_OFFSET, num_validators);

    let (block, mut state) = builder.build_with_n_exits(num_exits, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting TooYoung because validator has not been active for long enough when trying to exit
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::TooYoungToExit {
                current_epoch: Epoch::from(SLOT_OFFSET),
                earliest_exit_epoch: Epoch::from(2048 as u64)
            },
        })
    );
}

#[test]
fn invalid_exit_bad_signature() {
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
    assert_eq!(
        result,
        Err(BlockProcessingError::ExitInvalid {
            index: 0,
            reason: ExitInvalid::BadSignature,
        })
    );
}

fn get_builder(
    spec: &ChainSpec,
    slot_offset: u64,
    num_validators: usize,
) -> (BlockProcessingBuilder<MainnetEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(num_validators, &spec);

    // Set the state and block to be in the last slot of the `slot_offset`th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + slot_offset).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}
