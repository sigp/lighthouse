extern crate bls;
extern crate boolean_bitfield;
extern crate ethereum_types;
extern crate ssz;

pub mod test_utils;

pub mod attestation;
pub mod attestation_data;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_state;
pub mod candidate_pow_receipt_root_record;
pub mod casper_slashing;
pub mod crosslink_record;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_input;
pub mod exit;
pub mod fork_data;
pub mod pending_attestation_record;
pub mod proposal_signed_data;
pub mod proposer_slashing;
pub mod shard_committee;
pub mod shard_reassignment_record;
pub mod slashable_vote_data;
pub mod special_record;
pub mod validator_record;

pub mod readers;

use self::ethereum_types::{H160, H256, U256};
use std::collections::HashMap;

pub use crate::attestation::Attestation;
pub use crate::attestation_data::AttestationData;
pub use crate::beacon_block::BeaconBlock;
pub use crate::beacon_block_body::BeaconBlockBody;
pub use crate::beacon_state::BeaconState;
pub use crate::casper_slashing::CasperSlashing;
pub use crate::crosslink_record::CrosslinkRecord;
pub use crate::deposit::Deposit;
pub use crate::deposit_data::DepositData;
pub use crate::deposit_input::DepositInput;
pub use crate::exit::Exit;
pub use crate::fork_data::ForkData;
pub use crate::pending_attestation_record::PendingAttestationRecord;
pub use crate::proposal_signed_data::ProposalSignedData;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::shard_committee::ShardCommittee;
pub use crate::slashable_vote_data::SlashableVoteData;
pub use crate::special_record::{SpecialRecord, SpecialRecordKind};
pub use crate::validator_record::{StatusFlags as ValidatorStatusFlags, ValidatorRecord};

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = boolean_bitfield::BooleanBitfield;
pub type BitfieldError = boolean_bitfield::Error;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u64), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;
