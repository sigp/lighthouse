//! Ethereum 2.0 types

#[macro_use]
pub mod test_utils;

pub mod attestation;
pub mod attestation_data;
pub mod attestation_data_and_custody_bit;
pub mod attester_slashing;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_block_header;
pub mod beacon_state;
pub mod chain_spec;
pub mod crosslink;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_input;
pub mod eth1_data;
pub mod eth1_data_vote;
pub mod fork;
pub mod free_attestation;
pub mod pending_attestation;
pub mod proposal;
pub mod proposer_slashing;
pub mod readers;
pub mod shard_reassignment_record;
pub mod slashable_attestation;
pub mod transfer;
pub mod voluntary_exit;
#[macro_use]
pub mod slot_epoch_macros;
pub mod slot_epoch;
pub mod slot_height;
pub mod validator;
pub mod validator_registry;

use ethereum_types::{H160, H256, U256};
use std::collections::HashMap;

pub use crate::attestation::Attestation;
pub use crate::attestation_data::AttestationData;
pub use crate::attestation_data_and_custody_bit::AttestationDataAndCustodyBit;
pub use crate::attester_slashing::AttesterSlashing;
pub use crate::beacon_block::BeaconBlock;
pub use crate::beacon_block_body::BeaconBlockBody;
pub use crate::beacon_block_header::BeaconBlockHeader;
pub use crate::beacon_state::{BeaconState, Error as BeaconStateError, RelativeEpoch};
pub use crate::chain_spec::{ChainSpec, Domain};
pub use crate::crosslink::Crosslink;
pub use crate::deposit::Deposit;
pub use crate::deposit_data::DepositData;
pub use crate::deposit_input::DepositInput;
pub use crate::eth1_data::Eth1Data;
pub use crate::eth1_data_vote::Eth1DataVote;
pub use crate::fork::Fork;
pub use crate::free_attestation::FreeAttestation;
pub use crate::pending_attestation::PendingAttestation;
pub use crate::proposal::Proposal;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::slashable_attestation::SlashableAttestation;
pub use crate::slot_epoch::{Epoch, Slot};
pub use crate::slot_height::SlotHeight;
pub use crate::transfer::Transfer;
pub use crate::validator::Validator;
pub use crate::voluntary_exit::VoluntaryExit;

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;
pub type Bitfield = boolean_bitfield::BooleanBitfield;
pub type BitfieldError = boolean_bitfield::Error;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u64), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;

pub use bls::{AggregatePublicKey, AggregateSignature, Keypair, PublicKey, SecretKey, Signature};
