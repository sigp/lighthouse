extern crate active_validators;
extern crate honey_badger_split;
extern crate types;
extern crate vec_shuffle;

mod proposer;
mod shuffle;

pub use proposer::{block_proposer_for_slot, BlockProposerError, shard_and_committee_for_slot};
pub use shuffle::{
    shard_and_committees_for_cycle,
    ValidatorAssignmentError,
};
