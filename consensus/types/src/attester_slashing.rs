use crate::{test_utils::TestRandom, EthSpec, IndexedAttestation};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Base, Electra),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Eq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec"),
        arbitrary(bound = "E: EthSpec")
    )
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct AttesterSlashing<E: EthSpec> {
    pub attestation_1: IndexedAttestation<E>,
    pub attestation_2: IndexedAttestation<E>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    ssz_and_tree_hash_tests!(AttesterSlashing<MainnetEthSpec>);
}
