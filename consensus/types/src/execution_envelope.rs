use crate::test_utils::TestRandom;
use crate::*;
use beacon_block_body::KzgCommitments;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(EIP7732),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionEnvelope<E: EthSpec> {
    #[superstruct(only(EIP7732), partial_getter(rename = "payload_eip7732"))]
    pub payload: ExecutionPayloadEIP7732<E>,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub beacon_block_root: Hash256,
    pub blob_kzg_commitments: KzgCommitments<E>,
    pub payment_withheld: bool,
    pub state_root: Hash256,
}
