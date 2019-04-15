#![cfg(test)]
use super::block_processing_builder::BlockProcessingBuilder;
use super::errors::*;
use crate::per_block_processing;
use ssz::SignedRoot;
use types::{ChainSpec, Domain, Keypair, Signature, Slot};

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn valid_block_ok() {
    let spec = ChainSpec::foundation();
    let builder = get_builder(&spec);
    let (block, mut state) = builder.build(&spec);

    let result = per_block_processing(&mut state, &block, &spec);

    assert_eq!(result, Ok(()));
}

#[test]
fn invalid_block_header_state_slot() {
    let spec = ChainSpec::foundation();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(&spec);

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
#[ignore]
fn invalid_parent_block_root() {
    // this will be changed in spec 0.5.1 to use signed root
}

#[test]
fn invalid_block_signature() {
    let spec = ChainSpec::foundation();
    let builder = get_builder(&spec);
    let (mut block, mut state) = builder.build(&spec);

    // sign the block with a keypair that is not the expected proposer
    let keypair = Keypair::random();
    let message = block.signed_root();
    let epoch = block.slot.epoch(spec.slots_per_epoch);
    let domain = spec.get_domain(epoch, Domain::BeaconBlock, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);

    // process block with invalid block signature
    let result = per_block_processing(&mut state, &block, &spec);

    // should get a BadSignature error
    assert_eq!(
        result,
        Err(BlockProcessingError::Invalid(BlockInvalid::BadSignature))
    );
}

fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder) {
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.set_slot(last_slot_of_epoch, &spec);
    builder.build_caches(&spec);

    (builder)
}
