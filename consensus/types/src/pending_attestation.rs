use crate::test_utils::TestRandom;
use crate::{AttestationData, BitList, EthSpec};

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.12.1
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[arbitrary(bound = "E: EthSpec")]
pub struct PendingAttestation<E: EthSpec> {
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    #[serde(with = "serde_utils::quoted_u64")]
    pub inclusion_delay: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(PendingAttestation<MainnetEthSpec>);
}
