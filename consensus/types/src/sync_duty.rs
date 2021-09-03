use crate::{EthSpec, SyncCommittee, SyncSubnetId};
use bls::PublicKeyBytes;
use safe_arith::ArithError;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncDuty {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64_vec")]
    pub validator_sync_committee_indices: Vec<u64>,
}

impl SyncDuty {
    /// Create a new `SyncDuty` from the list of validator indices in a sync committee.
    pub fn from_sync_committee_indices(
        validator_index: u64,
        pubkey: PublicKeyBytes,
        sync_committee_indices: &[usize],
    ) -> Option<Self> {
        // Positions of the `validator_index` within the committee.
        let validator_sync_committee_indices = sync_committee_indices
            .iter()
            .enumerate()
            .filter_map(|(i, &v)| {
                if validator_index == v as u64 {
                    Some(i as u64)
                } else {
                    None
                }
            })
            .collect();
        Self::new(validator_index, pubkey, validator_sync_committee_indices)
    }

    /// Create a new `SyncDuty` from a `SyncCommittee`, which contains the pubkeys but not the
    /// indices.
    pub fn from_sync_committee<T: EthSpec>(
        validator_index: u64,
        pubkey: PublicKeyBytes,
        sync_committee: &SyncCommittee<T>,
    ) -> Option<Self> {
        let validator_sync_committee_indices = sync_committee
            .pubkeys
            .iter()
            .enumerate()
            .filter_map(|(i, committee_pubkey)| {
                if &pubkey == committee_pubkey {
                    Some(i as u64)
                } else {
                    None
                }
            })
            .collect();
        Self::new(validator_index, pubkey, validator_sync_committee_indices)
    }

    /// Create a duty if the `validator_sync_committee_indices` is non-empty.
    fn new(
        validator_index: u64,
        pubkey: PublicKeyBytes,
        validator_sync_committee_indices: Vec<u64>,
    ) -> Option<Self> {
        if !validator_sync_committee_indices.is_empty() {
            Some(SyncDuty {
                pubkey,
                validator_index,
                validator_sync_committee_indices,
            })
        } else {
            None
        }
    }

    /// Get the set of subnet IDs for this duty.
    pub fn subnet_ids<E: EthSpec>(&self) -> Result<HashSet<SyncSubnetId>, ArithError> {
        SyncSubnetId::compute_subnets_for_sync_committee::<E>(
            &self.validator_sync_committee_indices,
        )
    }
}
