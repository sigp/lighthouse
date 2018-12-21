extern crate bls;
extern crate boolean_bitfield;
extern crate ethereum_types;
extern crate ssz;

pub mod active_state;
pub mod attestation_data;
pub mod attestation;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_state;
pub mod candidate_pow_receipt_root_record;
pub mod casper_slashing;
pub mod chain_config;
pub mod crosslink_record;
pub mod crystallized_state;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_input;
pub mod exit;
pub mod fork_data;
pub mod pending_attestation_record;
pub mod proposal_signed_data;
pub mod proposer_slashing;
pub mod shard_and_committee;
pub mod shard_reassignment_record;
pub mod special_record;
pub mod slashable_vote_data;
pub mod validator_record;
pub mod validator_registration;

use self::ethereum_types::{H160, H256, U256};
use std::collections::HashMap;

pub use active_state::ActiveState;
pub use attestation_data::AttestationData;
pub use attestation::Attestation;
pub use beacon_block::BeaconBlock;
pub use beacon_block_body::BeaconBlockBody;
pub use beacon_state::BeaconState;
pub use casper_slashing::CasperSlashing;
pub use chain_config::ChainConfig;
pub use crosslink_record::CrosslinkRecord;
pub use crystallized_state::CrystallizedState;
pub use deposit::Deposit;
pub use deposit_data::DepositData;
pub use deposit_input::DepositInput;
pub use exit::Exit;
pub use fork_data::ForkData;
pub use pending_attestation_record::PendingAttestationRecord;
pub use proposal_signed_data::ProposalSignedData;
pub use proposer_slashing::ProposerSlashing;
pub use slashable_vote_data::SlashableVoteData;
pub use shard_and_committee::ShardAndCommittee;
pub use special_record::{SpecialRecord, SpecialRecordKind};
pub use validator_record::{ValidatorRecord, ValidatorStatus};
pub use validator_registration::ValidatorRegistration;

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = boolean_bitfield::BooleanBitfield;
pub type BitfieldError = boolean_bitfield::Error;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u16), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;
