//! Ethereum 2.0 types

// Required for big type-level numbers
#![recursion_limit = "128"]

#[macro_use]
pub mod test_utils;

pub mod attestation;
pub mod attestation_data;
pub mod attestation_data_and_custody_bit;
pub mod attestation_duty;
pub mod attester_slashing;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_block_header;
pub mod beacon_state;
pub mod chain_spec;
pub mod checkpoint;
pub mod compact_committee;
pub mod crosslink;
pub mod crosslink_committee;
pub mod deposit;
pub mod deposit_data;
pub mod eth1_data;
pub mod fork;
pub mod free_attestation;
pub mod historical_batch;
pub mod indexed_attestation;
pub mod pending_attestation;
pub mod proposer_slashing;
pub mod transfer;
pub mod utils;
pub mod voluntary_exit;
#[macro_use]
pub mod slot_epoch_macros;
pub mod relative_epoch;
pub mod slot_epoch;
pub mod slot_height;
pub mod validator;

use ethereum_types::{H160, H256, U256};
use std::collections::HashMap;

pub use crate::attestation::Attestation;
pub use crate::attestation_data::AttestationData;
pub use crate::attestation_data_and_custody_bit::AttestationDataAndCustodyBit;
pub use crate::attestation_duty::AttestationDuty;
pub use crate::attester_slashing::AttesterSlashing;
pub use crate::beacon_block::BeaconBlock;
pub use crate::beacon_block_body::BeaconBlockBody;
pub use crate::beacon_block_header::BeaconBlockHeader;
pub use crate::beacon_state::{Error as BeaconStateError, *};
pub use crate::chain_spec::{ChainSpec, Domain};
pub use crate::checkpoint::Checkpoint;
pub use crate::compact_committee::CompactCommittee;
pub use crate::crosslink::Crosslink;
pub use crate::crosslink_committee::{CrosslinkCommittee, OwnedCrosslinkCommittee};
pub use crate::deposit::Deposit;
pub use crate::deposit_data::DepositData;
pub use crate::eth1_data::Eth1Data;
pub use crate::fork::Fork;
pub use crate::free_attestation::FreeAttestation;
pub use crate::historical_batch::HistoricalBatch;
pub use crate::indexed_attestation::IndexedAttestation;
pub use crate::pending_attestation::PendingAttestation;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::relative_epoch::{Error as RelativeEpochError, RelativeEpoch};
pub use crate::slot_epoch::{Epoch, Slot};
pub use crate::slot_height::SlotHeight;
pub use crate::transfer::Transfer;
pub use crate::validator::Validator;
pub use crate::voluntary_exit::VoluntaryExit;

pub type Shard = u64;
pub type Committee = Vec<usize>;
pub type CrosslinkCommittees = Vec<(Committee, u64)>;

pub type Hash256 = H256;
pub type Address = H160;
pub type EthBalance = U256;

/// Maps a (slot, shard_id) to attestation_indices.
pub type AttesterMap = HashMap<(u64, u64), Vec<usize>>;

/// Maps a slot to a block proposer.
pub type ProposerMap = HashMap<u64, usize>;

pub use bls::{
    AggregatePublicKey, AggregateSignature, Keypair, PublicKey, PublicKeyBytes, SecretKey,
    Signature, SignatureBytes,
};
pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
