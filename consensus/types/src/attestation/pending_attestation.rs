use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::BitList;
#[cfg(feature = "testing")]
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[cfg(feature = "testing")]
use crate::test_utils::TestRandom;
use crate::{attestation::AttestationData, core::EthSpec, fork::ForkName};

/// An attestation that has been included in the state but not yet fully processed.
///
/// Spec v0.12.1
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[cfg_attr(feature = "testing", derive(TestRandom))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
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
