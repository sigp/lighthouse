use crate::test_utils::TestRandom;
use crate::{AttestationData, BitList, EthSpec};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.11.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct PendingAttestation<T: EthSpec> {
    pub aggregation_bits: BitList<T::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
    pub inclusion_delay: u64,
    pub proposer_index: u64,
}

#[cfg(feature = "arbitrary-fuzz")]
impl<T: EthSpec> arbitrary::Arbitrary for PendingAttestation<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            aggregation_bits: <BitList<T::MaxValidatorsPerCommittee>>::arbitrary(u)?,
            data: AttestationData::arbitrary(u)?,
            inclusion_delay: u64::arbitrary(u)?,
            proposer_index: u64::arbitrary(u)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(PendingAttestation<MainnetEthSpec>);
}
