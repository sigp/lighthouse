//! Ethereum 2.0 types
// Clippy lint set up
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
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
pub mod bls_to_execution_change;
pub mod builder_bid;
pub mod chain_spec;
pub mod checkpoint;
pub mod consts;
pub mod contribution_and_proof;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_message;
pub mod deposit_tree_snapshot;
pub mod enr_fork_id;
pub mod eth1_data;
pub mod eth_spec;
pub mod execution_block_hash;
pub mod execution_payload;
pub mod execution_payload_header;
pub mod fork;
pub mod fork_data;
pub mod fork_name;
pub mod fork_versioned_response;
pub mod graffiti;
pub mod historical_batch;
pub mod historical_summary;
pub mod indexed_attestation;
pub mod light_client_bootstrap;
pub mod light_client_finality_update;
pub mod light_client_optimistic_update;
pub mod light_client_update;
pub mod pending_attestation;
pub mod proposer_preparation_data;
pub mod proposer_slashing;
pub mod relative_epoch;
pub mod selection_proof;
pub mod shuffling_id;
pub mod signed_aggregate_and_proof;
pub mod signed_beacon_block;
pub mod signed_beacon_block_header;
pub mod signed_bls_to_execution_change;
pub mod signed_contribution_and_proof;
pub mod signed_voluntary_exit;
pub mod signing_data;
pub mod sync_committee_subscription;
pub mod sync_duty;
pub mod validator;
pub mod validator_subscription;
pub mod voluntary_exit;
pub mod withdrawal_credentials;
#[macro_use]
pub mod slot_epoch_macros;
pub mod config_and_preset;
pub mod execution_block_header;
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
pub mod withdrawal;

pub mod slot_data;
#[cfg(feature = "sqlite")]
pub mod sqlite;

pub mod blob_sidecar;
pub mod light_client_header;
pub mod non_zero_usize;
pub mod runtime_var_list;

use ethereum_types::{H160, H256};

pub use crate::aggregate_and_proof::AggregateAndProof;
pub use crate::attestation::{Attestation, Error as AttestationError};
pub use crate::attestation_data::AttestationData;
pub use crate::attestation_duty::AttestationDuty;
pub use crate::attester_slashing::AttesterSlashing;
pub use crate::beacon_block::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockCapella, BeaconBlockDeneb,
    BeaconBlockMerge, BeaconBlockRef, BeaconBlockRefMut, BlindedBeaconBlock, EmptyBlock,
};
pub use crate::beacon_block_body::{
    BeaconBlockBody, BeaconBlockBodyAltair, BeaconBlockBodyBase, BeaconBlockBodyCapella,
    BeaconBlockBodyDeneb, BeaconBlockBodyMerge, BeaconBlockBodyRef, BeaconBlockBodyRefMut,
};
pub use crate::beacon_block_header::BeaconBlockHeader;
pub use crate::beacon_committee::{BeaconCommittee, OwnedBeaconCommittee};
pub use crate::beacon_state::{BeaconTreeHashCache, Error as BeaconStateError, *};
pub use crate::blob_sidecar::{BlobSidecar, BlobSidecarList, BlobsList};
pub use crate::bls_to_execution_change::BlsToExecutionChange;
pub use crate::chain_spec::{ChainSpec, Config, Domain};
pub use crate::checkpoint::Checkpoint;
pub use crate::config_and_preset::{ConfigAndPreset, ConfigAndPresetCapella, ConfigAndPresetDeneb};
pub use crate::contribution_and_proof::ContributionAndProof;
pub use crate::deposit::{Deposit, DEPOSIT_TREE_DEPTH};
pub use crate::deposit_data::DepositData;
pub use crate::deposit_message::DepositMessage;
pub use crate::deposit_tree_snapshot::{DepositTreeSnapshot, FinalizedExecutionBlock};
pub use crate::enr_fork_id::EnrForkId;
pub use crate::eth1_data::Eth1Data;
pub use crate::eth_spec::EthSpecId;
pub use crate::execution_block_hash::ExecutionBlockHash;
pub use crate::execution_block_header::{EncodableExecutionBlockHeader, ExecutionBlockHeader};
pub use crate::execution_payload::{
    ExecutionPayload, ExecutionPayloadCapella, ExecutionPayloadDeneb, ExecutionPayloadMerge,
    ExecutionPayloadRef, Transaction, Transactions, Withdrawals,
};
pub use crate::execution_payload_header::{
    ExecutionPayloadHeader, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    ExecutionPayloadHeaderMerge, ExecutionPayloadHeaderRef, ExecutionPayloadHeaderRefMut,
};
pub use crate::fork::Fork;
pub use crate::fork_context::ForkContext;
pub use crate::fork_data::ForkData;
pub use crate::fork_name::{ForkName, InconsistentFork};
pub use crate::fork_versioned_response::{ForkVersionDeserialize, ForkVersionedResponse};
pub use crate::graffiti::{Graffiti, GRAFFITI_BYTES_LEN};
pub use crate::historical_batch::HistoricalBatch;
pub use crate::indexed_attestation::IndexedAttestation;
pub use crate::light_client_bootstrap::LightClientBootstrap;
pub use crate::light_client_finality_update::LightClientFinalityUpdate;
pub use crate::light_client_header::LightClientHeader;
pub use crate::light_client_optimistic_update::LightClientOptimisticUpdate;
pub use crate::light_client_update::{Error as LightClientError, LightClientUpdate};
pub use crate::participation_flags::ParticipationFlags;
pub use crate::participation_list::ParticipationList;
pub use crate::payload::{
    AbstractExecPayload, BlindedPayload, BlindedPayloadCapella, BlindedPayloadDeneb,
    BlindedPayloadMerge, BlindedPayloadRef, BlockType, ExecPayload, FullPayload,
    FullPayloadCapella, FullPayloadDeneb, FullPayloadMerge, FullPayloadRef, OwnedExecPayload,
};
pub use crate::pending_attestation::PendingAttestation;
pub use crate::preset::{AltairPreset, BasePreset, BellatrixPreset, CapellaPreset, DenebPreset};
pub use crate::proposer_preparation_data::ProposerPreparationData;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::relative_epoch::{Error as RelativeEpochError, RelativeEpoch};
pub use crate::runtime_var_list::RuntimeVariableList;
pub use crate::selection_proof::SelectionProof;
pub use crate::shuffling_id::AttestationShufflingId;
pub use crate::signed_aggregate_and_proof::SignedAggregateAndProof;
pub use crate::signed_beacon_block::{
    ssz_tagged_signed_beacon_block, ssz_tagged_signed_beacon_block_arc, SignedBeaconBlock,
    SignedBeaconBlockAltair, SignedBeaconBlockBase, SignedBeaconBlockCapella,
    SignedBeaconBlockDeneb, SignedBeaconBlockHash, SignedBeaconBlockMerge,
    SignedBlindedBeaconBlock,
};
pub use crate::signed_beacon_block_header::SignedBeaconBlockHeader;
pub use crate::signed_bls_to_execution_change::SignedBlsToExecutionChange;
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
pub use crate::withdrawal::Withdrawal;
pub use crate::withdrawal_credentials::WithdrawalCredentials;

pub type CommitteeIndex = u64;
pub type Hash256 = H256;
pub type Uint256 = ethereum_types::U256;
pub type Address = H160;
pub type ForkVersion = [u8; 4];
pub type BLSFieldElement = Uint256;
pub type Blob<T> = FixedVector<u8, <T as EthSpec>::BytesPerBlob>;
pub type KzgProofs<T> = VariableList<KzgProof, <T as EthSpec>::MaxBlobCommitmentsPerBlock>;
pub type VersionedHash = Hash256;
pub type Hash64 = ethereum_types::H64;

pub use bls::{
    AggregatePublicKey, AggregateSignature, Keypair, PublicKey, PublicKeyBytes, SecretKey,
    Signature, SignatureBytes,
};

pub use kzg::{KzgCommitment, KzgProof, VERSIONED_HASH_VERSION_KZG};

pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
pub use superstruct::superstruct;
