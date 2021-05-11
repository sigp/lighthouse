//! Ethereum 2.0 types

// Required for big type-level numbers
#![recursion_limit = "128"]
// Clippy lint set up
#![cfg_attr(
    not(test),
    deny(
        clippy::integer_arithmetic,
        clippy::disallowed_method,
        clippy::indexing_slicing
    )
)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
pub mod test_utils;

pub mod aggregate_and_proof;
pub mod attestation;
pub mod attestation_data;
pub mod attestation_duty;
pub mod attester_slashing;
pub mod beacon_block;
pub mod beacon_block_body;
pub mod beacon_block_header;
pub mod beacon_committee;
pub mod beacon_state;
pub mod chain_spec;
pub mod checkpoint;
pub mod consts;
pub mod deposit;
pub mod deposit_data;
pub mod deposit_message;
pub mod enr_fork_id;
pub mod eth1_data;
pub mod eth_spec;
pub mod fork;
pub mod fork_data;
pub mod fork_name;
pub mod free_attestation;
pub mod graffiti;
pub mod historical_batch;
pub mod indexed_attestation;
pub mod pending_attestation;
pub mod proposer_slashing;
pub mod relative_epoch;
pub mod selection_proof;
pub mod shuffling_id;
pub mod signed_aggregate_and_proof;
pub mod signed_beacon_block;
pub mod signed_beacon_block_header;
pub mod signed_voluntary_exit;
pub mod signing_data;
pub mod validator;
pub mod validator_subscription;
pub mod voluntary_exit;
#[macro_use]
pub mod slot_epoch_macros;
pub mod fork_context;
pub mod participation_flags;
pub mod slot_epoch;
pub mod subnet_id;
pub mod sync_aggregate;
pub mod sync_committee;
mod tree_hash_impls;

#[cfg(feature = "sqlite")]
pub mod sqlite;

use ethereum_types::{H160, H256};

pub use crate::aggregate_and_proof::AggregateAndProof;
pub use crate::attestation::{Attestation, Error as AttestationError};
pub use crate::attestation_data::AttestationData;
pub use crate::attestation_duty::AttestationDuty;
pub use crate::attester_slashing::AttesterSlashing;
pub use crate::beacon_block::{
    BeaconBlock, BeaconBlockAltair, BeaconBlockBase, BeaconBlockRef, BeaconBlockRefMut,
};
pub use crate::beacon_block_body::{
    BeaconBlockBody, BeaconBlockBodyAltair, BeaconBlockBodyBase, BeaconBlockBodyRef,
    BeaconBlockBodyRefMut,
};
pub use crate::beacon_block_header::BeaconBlockHeader;
pub use crate::beacon_committee::{BeaconCommittee, OwnedBeaconCommittee};
pub use crate::beacon_state::{BeaconTreeHashCache, Error as BeaconStateError, *};
pub use crate::chain_spec::{AltairConfig, BaseConfig, ChainSpec, Domain, StandardConfig};
pub use crate::checkpoint::Checkpoint;
pub use crate::deposit::{Deposit, DEPOSIT_TREE_DEPTH};
pub use crate::deposit_data::DepositData;
pub use crate::deposit_message::DepositMessage;
pub use crate::enr_fork_id::EnrForkId;
pub use crate::eth1_data::Eth1Data;
pub use crate::eth_spec::EthSpecId;
pub use crate::fork::Fork;
pub use crate::fork_context::ForkContext;
pub use crate::fork_data::ForkData;
pub use crate::fork_name::ForkName;
pub use crate::free_attestation::FreeAttestation;
pub use crate::graffiti::{Graffiti, GRAFFITI_BYTES_LEN};
pub use crate::historical_batch::HistoricalBatch;
pub use crate::indexed_attestation::IndexedAttestation;
pub use crate::participation_flags::ParticipationFlags;
pub use crate::pending_attestation::PendingAttestation;
pub use crate::proposer_slashing::ProposerSlashing;
pub use crate::relative_epoch::{Error as RelativeEpochError, RelativeEpoch};
pub use crate::selection_proof::SelectionProof;
pub use crate::shuffling_id::AttestationShufflingId;
pub use crate::signed_aggregate_and_proof::SignedAggregateAndProof;
pub use crate::signed_beacon_block::{
    SignedBeaconBlock, SignedBeaconBlockAltair, SignedBeaconBlockBase, SignedBeaconBlockHash,
};
pub use crate::signed_beacon_block_header::SignedBeaconBlockHeader;
pub use crate::signed_voluntary_exit::SignedVoluntaryExit;
pub use crate::signing_data::{SignedRoot, SigningData};
pub use crate::slot_epoch::{Epoch, Slot};
pub use crate::subnet_id::SubnetId;
pub use crate::sync_aggregate::SyncAggregate;
pub use crate::sync_committee::SyncCommittee;
pub use crate::validator::Validator;
pub use crate::validator_subscription::ValidatorSubscription;
pub use crate::voluntary_exit::VoluntaryExit;

pub type CommitteeIndex = u64;
pub type Hash256 = H256;
pub type Address = H160;
pub type ForkVersion = [u8; 4];

pub use bls::{
    AggregatePublicKey, AggregateSignature, Keypair, PublicKey, PublicKeyBytes, SecretKey,
    Signature, SignatureBytes,
};
pub use ssz_types::{typenum, typenum::Unsigned, BitList, BitVector, FixedVector, VariableList};
pub use superstruct::superstruct;
