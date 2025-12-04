//! Ethereum Consensus types
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
pub mod test_utils;

pub mod attestation;
pub mod block;
pub mod builder;
pub mod consolidation;
pub mod core;
pub mod data;
pub mod deposit;
pub mod execution;
pub mod exit;
pub mod fork;
pub mod kzg_ext;
pub mod light_client;
pub mod slashing;
pub mod state;
pub mod sync_committee;
pub mod validator;
pub mod withdrawal;

// Temporary root level exports to maintain backwards compatibility for Lighthouse.
pub use attestation::*;
pub use block::*;
pub use builder::*;
pub use consolidation::*;
pub use core::{consts, *};
pub use data::*;
pub use deposit::*;
pub use execution::*;
pub use exit::*;
pub use fork::*;
pub use kzg_ext::*;
pub use light_client::*;
pub use slashing::*;
pub use state::*;
pub use sync_committee::*;
pub use validator::*;
pub use withdrawal::*;

// Temporary facade modules to maintain backwards compatibility for Lighthouse.
pub mod eth_spec {
    pub use crate::core::EthSpec;
}

pub mod chain_spec {
    pub use crate::core::ChainSpec;
}

pub mod beacon_block {
    pub use crate::block::{BlindedBeaconBlock, BlockImportSource};
}

pub mod beacon_block_body {
    pub use crate::kzg_ext::{KzgCommitments, format_kzg_commitments};
}

pub mod beacon_state {
    pub use crate::state::{
        BeaconState, BeaconStateBase, CommitteeCache, compute_committee_index_in_epoch,
        compute_committee_range_in_epoch, epoch_committee_count,
    };
}

pub mod graffiti {
    pub use crate::core::GraffitiString;
}

pub mod indexed_attestation {
    pub use crate::attestation::{IndexedAttestationBase, IndexedAttestationElectra};
}

pub mod historical_summary {
    pub use crate::state::HistoricalSummary;
}

pub mod participation_flags {
    pub use crate::attestation::ParticipationFlags;
}

pub mod epoch_cache {
    pub use crate::state::{EpochCache, EpochCacheError, EpochCacheKey};
}

pub mod non_zero_usize {
    pub use crate::core::new_non_zero_usize;
}

pub mod data_column_sidecar {
    pub use crate::data::{
        Cell, ColumnIndex, DataColumn, DataColumnSidecar, DataColumnSidecarError,
        DataColumnSidecarList,
    };
}

pub mod builder_bid {
    pub use crate::builder::*;
}

pub mod blob_sidecar {
    pub use crate::data::{
        BlobIdentifier, BlobSidecar, BlobSidecarError, BlobsList, FixedBlobSidecarList,
    };
}

pub mod payload {
    pub use crate::execution::BlockProductionVersion;
}

pub mod execution_requests {
    pub use crate::execution::{
        ConsolidationRequests, DepositRequests, ExecutionRequests, RequestType, WithdrawalRequests,
    };
}

pub mod data_column_custody_group {
    pub use crate::data::{
        CustodyIndex, compute_columns_for_custody_group, compute_ordered_custody_column_indices,
        compute_subnets_for_node, compute_subnets_from_custody_group, get_custody_groups,
    };
}

pub mod sync_aggregate {
    pub use crate::sync_committee::SyncAggregateError as Error;
}

pub mod light_client_update {
    pub use crate::light_client::consts::{
        CURRENT_SYNC_COMMITTEE_INDEX, CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA, FINALIZED_ROOT_INDEX,
        FINALIZED_ROOT_INDEX_ELECTRA, MAX_REQUEST_LIGHT_CLIENT_UPDATES, NEXT_SYNC_COMMITTEE_INDEX,
        NEXT_SYNC_COMMITTEE_INDEX_ELECTRA,
    };
}

pub mod sync_committee_contribution {
    pub use crate::sync_committee::{
        SyncCommitteeContributionError as Error, SyncContributionData,
    };
}

pub mod slot_data {
    pub use crate::core::SlotData;
}

pub mod signed_aggregate_and_proof {
    pub use crate::attestation::SignedAggregateAndProofRefMut;
}

pub mod application_domain {
    pub use crate::core::ApplicationDomain;
}

// Temporary re-exports to maintain backwards compatibility for Lighthouse.
pub use crate::kzg_ext::consts::VERSIONED_HASH_VERSION_KZG;
pub use crate::light_client::LightClientError as LightClientUpdateError;
pub use crate::state::BeaconStateError as Error;
