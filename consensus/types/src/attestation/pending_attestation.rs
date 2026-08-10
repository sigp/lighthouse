use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::BitList;
use tree_hash_derive::TreeHash;

use crate::{attestation::AttestationData, core::Spec, fork::ForkName};

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct PendingAttestation {
    pub aggregation_bits: BitList<typenum::U<{ Spec::MAX_VALIDATORS_PER_COMMITTEE }>>,
    pub data: AttestationData,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inclusion_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PendingAttestation);
}
