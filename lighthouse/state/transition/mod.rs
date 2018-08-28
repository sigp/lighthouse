use super::super::utils::types::Hash256;
use super::chain_config::ChainConfig;
use super::shard_and_committee::ShardAndCommittee;
use super::validator_record::ValidatorRecord;

mod attestation_parent_hashes;
mod shuffling;
mod validator_allocation;

pub use self::attestation_parent_hashes::attestation_parent_hashes;
pub use self::validator_allocation::get_new_shuffling;
pub use self::shuffling::shuffle;

#[derive(Debug)]
pub enum TransitionError {
    IntWrapping,
    OutOfBounds,
    InvalidInput(String),
}



