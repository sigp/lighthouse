extern crate ethereum_types;
extern crate bls;
extern crate boolean_bitfield;
extern crate ssz;

pub mod active_state;
pub mod attestation_record;
pub mod crystallized_state;
pub mod chain_config;
pub mod block;
pub mod crosslink_record;
pub mod shard_and_committee;
pub mod validator_record;

use self::ethereum_types::{
    H256,
    H160,
    U256
};
use self::boolean_bitfield::BooleanBitfield;
use std::collections::HashMap;

pub use active_state::ActiveState;
pub use attestation_record::AttestationRecord;
pub use crystallized_state::CrystallizedState;
pub use chain_config::ChainConfig;
pub use block::Block;
pub use crosslink_record::CrosslinkRecord;
pub use shard_and_committee::ShardAndCommittee;
pub use validator_record::ValidatorRecord;

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = BooleanBitfield;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u16), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
