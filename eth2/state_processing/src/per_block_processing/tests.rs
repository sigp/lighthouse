#![cfg(test)]
use crate::per_block_processing;
use super::block_processing_builder::BlockProcessingBuilder;
use types::*;

pub const VALIDATOR_COUNT: usize = 10;

#[test]
fn runs_without_error() {
    let spec = ChainSpec::foundation();
    let mut builder = BlockProcessingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.set_slot(last_slot_of_epoch, &spec);
    
    builder.build_caches(&spec);
    
    let (block, mut state) = builder.build(&spec);

    per_block_processing(&mut state, &block, &spec).unwrap();
}

