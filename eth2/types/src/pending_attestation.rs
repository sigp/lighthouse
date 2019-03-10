use crate::test_utils::TestRandom;
use crate::{AttestationData, Bitfield, Slot};
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.4.0
#[derive(Debug, Clone, PartialEq, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct PendingAttestation {
    pub aggregation_bitfield: Bitfield,
    pub data: AttestationData,
    pub custody_bitfield: Bitfield,
    pub inclusion_slot: Slot,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(PendingAttestation);
}
