use crate::test_utils::TestRandom;
use crate::*;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    TestRandom,
    TreeHash,
    Debug,
    Clone,
    PartialEq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct IndexedPayloadAttestation<E: EthSpec> {
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub attesting_indices: VariableList<u64, E::PTCSize>,
    pub data: PayloadAttestationData,
    signature: AggregateSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(IndexedPayloadAttestation<MainnetEthSpec>);
}
