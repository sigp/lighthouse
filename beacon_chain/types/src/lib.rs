extern crate ethereum_types;
extern crate bls;
extern crate boolean_bitfield;
extern crate ssz;

pub mod active_state;
pub mod attestation_record;
pub mod crystallized_state;
pub mod chain_config;
pub mod beacon_block;
pub mod crosslink_record;
pub mod shard_and_committee;
pub mod special_record;
pub mod validator_record;

use self::ethereum_types::{
    H256,
    H160,
    U256,
};
use self::boolean_bitfield::BooleanBitfield;
use std::collections::HashMap;

pub use active_state::ActiveState;
pub use attestation_record::AttestationRecord;
pub use crystallized_state::CrystallizedState;
pub use chain_config::ChainConfig;
pub use beacon_block::BeaconBlock;
pub use crosslink_record::CrosslinkRecord;
pub use shard_and_committee::ShardAndCommittee;
pub use special_record::{ SpecialRecord, SpecialRecordKind };
pub use validator_record::{ ValidatorRecord, ValidatorStatus };

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = BooleanBitfield;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u16), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;
