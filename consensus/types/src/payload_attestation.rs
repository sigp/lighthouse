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
    Eq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct PayloadAttestation<E: EthSpec> {
    pub aggregation_bits: BitList<E::PTCSize>,
    pub slot: Slot,
    pub payload_status: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestation<MainnetEthSpec>);
}
