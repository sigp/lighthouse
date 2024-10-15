// use crate::metrics;
// use crate::observed_aggregates::AsReference;
// use itertools::Itertools;
// use smallvec::SmallVec;
// use std::collections::HashMap;
// use tree_hash::{MerkleHasher, TreeHash, TreeHashType};
// use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
// use types::slot_data::SlotData;
// use types::sync_committee_contribution::SyncContributionData;
// use types::{
//     Attestation, AttestationData, AttestationRef, CommitteeIndex, EthSpec, Hash256, Slot,
//     SyncCommitteeContribution,
// };

// type AttestationKeyRoot = Hash256;
// type SyncDataRoot = Hash256;

// /// Post-Electra, we need a new key for Attestations that includes the committee index
// #[derive(Debug, Clone, PartialEq)]
// pub struct AttestationKey {
//     data_root: Hash256,
//     committee_index: Option<CommitteeIndex>,
//     slot: Slot,
// }
