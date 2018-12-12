extern crate active_validators;
extern crate honey_badger_split;
extern crate spec;
extern crate types;
extern crate vec_shuffle;

mod shuffle;

pub use shuffle::{shard_and_committees_for_cycle, ValidatorAssignmentError};
