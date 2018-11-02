extern crate active_validators;
extern crate honey_badger_split;
extern crate vec_shuffle;
extern crate types;

mod proposer;
mod shuffle;

pub use proposer::{block_proposer_for_slot, BlockProposerError};
pub use shuffle::{
    shard_and_committees_for_cycle,
    ValidatorAssignmentError,
};
