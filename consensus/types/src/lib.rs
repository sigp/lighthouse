//! Ethereum 2.0 types

// Required for big type-level numbers
#![recursion_limit = "128"]
// Clippy lint set up
#![cfg_attr(
    not(test),
    deny(
        clippy::integer_arithmetic,
        clippy::disallowed_methods,
        clippy::indexing_slicing
    )
)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
pub mod test_utils;

pub mod aggregate_and_proof;
pub mod application_domain;
pub mod attestation;
pub mod attestation_data;
pub mod attestation_duty;
pub mod attester_slashing;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_block_header;
pub mod beacon_committee;
pub mod beacon_state;
pub mod builder_bid;
pub mod chain_spec;
pub mod checkpoint;
pub mod consts;
pub mod contribution_and_proof;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_message;
pub mod enr_fork_id;
pub mod eth1_data;
pub mod eth_spec;
pub mod execution_block_hash;
pub mod execution_payload;
pub mod execution_payload_header;
pub mod fork;
pub mod fork_data;
pub mod fork_name;
pub mod free_attestation;
pub mod graffiti;
pub mod historical_batch;
pub mod indexed_attestation;
pub mod pending_attestation;
pub mod proposer_preparation_data;
pub mod proposer_slashing;
pub mod relative_epoch;
pub mod selection_proof;
pub mod shuffling_id;
pub mod signed_aggregate_and_proof;
pub mod signed_beacon_block;
pub mod signed_beacon_block_header;
pub mod signed_contribution_and_proof;
pub mod signed_voluntary_exit;
pub mod signing_data;
pub mod sync_committee_subscription;
pub mod sync_duty;
pub mod validator;
pub mod validator_subscription;
pub mod voluntary_exit;
#[macro_use]
pub mod slot_epoch_macros;
pub mod config_and_preset;
pub mod fork_context;
pub mod participation_flags;
pub mod participation_list;
pub mod payload;
pub mod preset;
pub mod slot_epoch;
pub mod subnet_id;
pub mod sync_aggregate;
pub mod sync_aggregator_selection_data;
pub mod sync_committee;
pub mod sync_committee_contribution;
pub mod sync_committee_message;
pub mod sync_selection_proof;
pub mod sync_subnet_id;
mod tree_hash_impls;
pub mod validator_registration_data;

mod blob_wrapper;
mod kzg_commitment;
pub mod slot_data;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub use kzg_commitment::KZGCommitment;

use ethereum_types::{H160, H256};

pub use crate::aggregate_and_proof::AggregateAndProof;
pub use crate::attestation::{Attestation, Error as AttestationError};
pub use crate::attestation_data::AttestationData;
pub use crate::attestation_duty::AttestationDuty;
pub use crate::attester_slashing::AttesterSlashing;
pub use crate::beacon_block::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockShanghai, BeaconBlockMerge, BeaconBlockRef,
    BeaconBlockRefMut, BlindedBeaconBlock,
};
pub use crate::beacon_block_body::{
    BeaconBlockBody, BeaconBlockBodyAltair, BeaconBlockBodyBase, BeaconBlockBodyMerge,
    BeaconBlockBodyRef, BeaconBlockBodyRefMut, BeaconBlockBodyShanghai,
};
pub use crate::beacon_block_header::BeaconBlockHeader;
pub use crate::beacon_committee::{BeaconCommittee, OwnedBeaconCommittee};
pub use crate::beacon_state::{BeaconTreeHashCache, Error as BeaconStateError, *};
pub use crate::blob_wrapper::BlobWrapper;
pub use crate::chain_spec::{ChainSpec, Config, Domain};
pub use crate::checkpoint::Checkpoint;
pub use crate::config_and_preset::{
    ConfigAndPreset, ConfigAndPresetAltair, ConfigAndPresetBellatrix,
};
pub use crate::contribution_and_proof::ContributionAndProof;
pub use crate::deposit::{Deposit, DEPOSIT_TREE_DEPTH};
pub use crate::deposit_data::DepositData;
pub use crate::deposit_message::DepositMessage;
pub use crate::enr_fork_id::EnrForkId;
pub use crate::eth1_data::Eth1Data;
pub use crate::eth_spec::EthSpecId;
pub use crate::execution_block_hash::ExecutionBlockHash;
pub use crate::execution_payload::{ExecutionPayload, Transaction, Transactions};
pub use crate::execution_payload_header::ExecutionPayloadHeader;
pub use crate::fork::Fork;
pub use crate::fork_context::ForkContext;
pub use crate::fork_data::ForkData;
pub use crate::fork_name::{ForkName, InconsistentFork};
pub use crate::free_attestation::FreeAttestation;
pub use crate::graffiti::{Graffiti, GRAFFITI_BYTES_LEN};
pub use crate::historical_batch::HistoricalBatch;
pub use crate::indexed_attestation::IndexedAttestation;
pub use crate::participation_flags::ParticipationFlags;
pub use crate::participation_list::ParticipationList;
pub use crate::payload::{BlindedPayload, BlockType, ExecPayload, FullPayload};
pub use crate::pending_attestation::PendingAttestation;
pub use crate::preset::{AltairPreset, BasePreset, BellatrixPreset};
pub use crate::proposer_preparation_data::ProposerPreparationData;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::relative_epoch::{Error as RelativeEpochError, RelativeEpoch};
pub use crate::selection_proof::SelectionProof;
pub use crate::shuffling_id::AttestationShufflingId;
pub use crate::signed_aggregate_and_proof::SignedAggregateAndProof;
pub use crate::signed_beacon_block::{
    SignedBeaconBlock, SignedBeaconBlockAltair, SignedBeaconBlockBase, SignedBeaconBlockHash,
    SignedBeaconBlockMerge, SignedBlindedBeaconBlock,SignedBeaconBlockShanghai
};
pub use crate::signed_beacon_block_header::SignedBeaconBlockHeader;
pub use crate::signed_contribution_and_proof::SignedContributionAndProof;
pub use crate::signed_voluntary_exit::SignedVoluntaryExit;
pub use crate::signing_data::{SignedRoot, SigningData};
pub use crate::slot_epoch::{Epoch, Slot};
pub use crate::subnet_id::SubnetId;
pub use crate::sync_aggregate::SyncAggregate;
pub use crate::sync_aggregator_selection_data::SyncAggregatorSelectionData;
pub use crate::sync_committee::SyncCommittee;
pub use crate::sync_committee_contribution::{SyncCommitteeContribution, SyncContributionData};
pub use crate::sync_committee_message::SyncCommitteeMessage;
pub use crate::sync_committee_subscription::SyncCommitteeSubscription;
pub use crate::sync_duty::SyncDuty;
pub use crate::sync_selection_proof::SyncSelectionProof;
pub use crate::sync_subnet_id::SyncSubnetId;
pub use crate::validator::Validator;
pub use crate::validator_registration_data::*;
pub use crate::validator_subscription::ValidatorSubscription;
pub use crate::voluntary_exit::VoluntaryExit;
use serde_big_array::BigArray;

pub type CommitteeIndex = u64;
pub type Hash256 = H256;
pub type Uint256 = ethereum_types::U256;
pub type Address = H160;
pub type ForkVersion = [u8; 4];
pub type BLSFieldElement = Uint256;
pub type Blob<T> = FixedVector<BLSFieldElement, T>;

pub use bls::{
    AggregatePublicKey, AggregateSignature, Keypair, PublicKey, PublicKeyBytes, SecretKey,
    Signature, SignatureBytes,
};
pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
pub use superstruct::superstruct;
