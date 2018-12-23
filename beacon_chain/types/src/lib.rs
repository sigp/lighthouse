extern crate bls;
extern crate boolean_bitfield;
extern crate ethereum_types;
extern crate ssz;

pub mod active_state;
pub mod attestation_data;
pub mod attestation;
pub mod beacon_block;
pub mod beacon_state;
pub mod candidate_pow_receipt_root_record;
pub mod chain_config;
pub mod crosslink_record;
pub mod crystallized_state;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_input;
pub mod fork_data;
pub mod pending_attestation_record;
pub mod shard_and_committee;
pub mod shard_reassignment_record;
pub mod special_record;
pub mod validator_record;

use self::ethereum_types::{H160, H256, U256};
use std::collections::HashMap;

pub use crate::active_state::ActiveState;
pub use crate::attestation_data::AttestationData;
pub use crate::attestation::Attestation;
pub use crate::beacon_block::BeaconBlock;
pub use crate::beacon_state::BeaconState;
pub use crate::chain_config::ChainConfig;
pub use crate::crosslink_record::CrosslinkRecord;
pub use crate::crystallized_state::CrystallizedState;
pub use crate::deposit::Deposit;
pub use crate::deposit_data::DepositData;
pub use crate::deposit_input::DepositInput;
pub use crate::fork_data::ForkData;
pub use crate::pending_attestation_record::PendingAttestationRecord;
pub use crate::shard_and_committee::ShardAndCommittee;
pub use crate::special_record::{SpecialRecord, SpecialRecordKind};
pub use crate::validator_record::{ValidatorRecord, ValidatorStatus};

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = boolean_bitfield::BooleanBitfield;
pub type BitfieldError = boolean_bitfield::Error;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u16), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;
