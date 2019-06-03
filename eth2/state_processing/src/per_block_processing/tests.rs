#![cfg(all(test, not(feature = "fake_crypto")))]
use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::per_block_processing;
use tree_hash::SignedRoot;
use types::*;

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn valid_block_ok() {
    let spec = FoundationEthSpec::spec();
    let builder = get_builder(&spec);
    let (block, mut state) = builder.build(None, None, &spec);

    let result = per_block_processing(&mut state, &block, &spec);

    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_block_header_state_slot() {
    let spec = FoundationEthSpec::spec();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(None, None, &spec);

    state.slot = Slot::new(133713);
    block.slot = Slot::new(424242);

    let result = per_block_processing(&mut state, &block, &spec);

    assert_eq!(
        result,
        Err(BlockProcessingError::Invalid(
            BlockInvalid::StateSlotMismatch
        ))
    );
}

#[test]
fn invalid_parent_block_root() {
    let spec = FoundationEthSpec::spec();
    let builder = get_builder(&spec);
    let invalid_parent_root = Hash256::from([0xAA; 32]);
    let (block, mut state) = builder.build(None, Some(invalid_parent_root), &spec);

    let result = per_block_processing(&mut state, &block, &spec);

    assert_eq!(
        result,
        Err(BlockProcessingError::Invalid(
            BlockInvalid::ParentBlockRootMismatch {
                state: Hash256::from_slice(&state.latest_block_header.signed_root()),
                block: block.previous_block_root
            }
        ))
    );
}

#[test]
fn invalid_block_signature() {
    let spec = FoundationEthSpec::spec();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(None, None, &spec);

    // sign the block with a keypair that is not the expected proposer
    let keypair = Keypair::random();
    let message = block.signed_root();
    let epoch = block.slot.epoch(spec.slots_per_epoch);
    let domain = spec.get_domain(epoch, Domain::BeaconProposer, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);

    // process block with invalid block signature
    let result = per_block_processing(&mut state, &block, &spec);

    // should get a BadSignature error
    assert_eq!(
        result,
        Err(BlockProcessingError::Invalid(BlockInvalid::BadSignature))
    );
}

#[test]
fn invalid_randao_reveal_signature() {
    let spec = FoundationEthSpec::spec();
    let builder = get_builder(&spec);

    // sign randao reveal with random keypair
    let keypair = Keypair::random();
    let (block, mut state) = builder.build(Some(keypair.sk), None, &spec);

    let result = per_block_processing(&mut state, &block, &spec);

    // should get a BadRandaoSignature error
    assert_eq!(
        result,
        Err(BlockProcessingError::Invalid(
            BlockInvalid::BadRandaoSignature
        ))
    );
}

fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder<FoundationEthSpec>) {
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.set_slot(last_slot_of_epoch, &spec);
    builder.build_caches(&spec);

    (builder)
}
