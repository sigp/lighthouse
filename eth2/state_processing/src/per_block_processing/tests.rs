#![cfg(all(test, not(feature = "fake_crypto")))]

use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::{per_block_processing, BlockSignatureStrategy};
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::{DepositTestTask};

pub const VALIDATOR_COUNT: usize = 10;
pub const NUM_DEPOSITS: u64 = 1;

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
fn valid_4_deposits() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(4, test_task, None, None, &spec);

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
fn valid_insert_max_deposits_plus_one() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::Valid;
    let num_deposits = <MainnetEthSpec as EthSpec>::MaxDeposits::to_u64() + 1;

    let (block, mut state) = builder.build_with_n_deposits(num_deposits, test_task, None, None, &spec);

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
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

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
    assert_eq!(result, Err(BlockProcessingError::DepositCountInvalid {
        expected: big_deposit_count as usize,
        found: 1
    }));
}

#[test]
fn invalid_deposit_deposit_count_too_small() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

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
    assert_eq!(result, Err(BlockProcessingError::DepositCountInvalid {
        expected: small_deposit_count as usize,
        found: 1
    }));
}

#[test]
fn invalid_deposit_deposit_bad_merkle_proof() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::Valid;

    let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

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
    assert_eq!(result, Err(BlockProcessingError::DepositInvalid {
        index: state.eth1_deposit_index as usize - 1,
        reason: DepositInvalid::BadMerkleProof
    }));
}

#[test]
fn invalid_deposit_wrong_pubkey() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::BadPubKey;

    let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    // Expecting BadSignature because the public key provided does not correspond to the correct public key
    assert_eq!(result, Err(BlockProcessingError::DepositInvalid {
        index: state.eth1_deposit_index as usize - 1,
        reason: DepositInvalid::BadSignature
    }));
}

#[test]
fn invalid_deposit_wrong_sig() {
    let spec = MainnetEthSpec::default_spec();
    let builder = get_builder(&spec);
    let test_task = DepositTestTask::BadSig;

    let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);

    // Expecting BadSignature because the block signature does not correspond to the correct public key
    let result = per_block_processing(
        &mut state,
        &block,
        None,
        BlockSignatureStrategy::VerifyIndividual,
        &spec,
    );

    assert_eq!(result, Err(BlockProcessingError::DepositInvalid {
        index: state.eth1_deposit_index as usize - 1,
        reason: DepositInvalid::BadSignature
    }));
}

// #[test]
// fn invalid_deposit_invalid_pub_key() {
    // let spec = MainnetEthSpec::default_spec();
    // let builder = get_builder(&spec);
    // let test_task = DepositTestTask::InvalidPubKey;
// 
    // let (block, mut state) = builder.build_with_n_deposits(NUM_DEPOSITS, test_task, None, None, &spec);
// 
    // let result = per_block_processing(
        // &mut state,
        // &block,
        // None,
        // BlockSignatureStrategy::VerifyIndividual,
        // &spec,
    // );
// 
    // assert_eq!(result, Ok(()));
// }


fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder<MainnetEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch =
        (MainnetEthSpec::genesis_epoch() + 4).end_slot(MainnetEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch);
    builder.build_caches(&spec);

    (builder)
}
