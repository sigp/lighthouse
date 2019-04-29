use crate::test_utils::TestRandom;
use crate::{Attestation, AttestationData, Bitfield, Slot};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::{CachedTreeHash, TreeHash};

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.6.0
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
    TestRandom,
)]
pub struct PendingAttestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub inclusion_slot: Slot,
    pub proposer_index: u64,
}

impl PendingAttestation {
    /// Create a `PendingAttestation` from an `Attestation`.
    pub fn from_attestation(
        attestation: &Attestation,
        inclusion_slot: Slot,
        proposer_index: u64,
    ) -> Self {
        PendingAttestation {
            data: attestation.data.clone(),
            aggregation_bitfield: attestation.aggregation_bitfield.clone(),
            inclusion_slot,
            proposer_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(PendingAttestation);
    cached_tree_hash_tests!(PendingAttestation);
}
