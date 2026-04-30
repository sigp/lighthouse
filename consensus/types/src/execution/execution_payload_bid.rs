use crate::kzg_ext::KzgCommitments;
use crate::state::BeaconStateError;
use crate::test_utils::TestRandom;
use crate::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::BitVector;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
        context_deserialize(ForkName),
    ),
    ref_attributes(
        derive(PartialEq, TreeHash, Debug),
        tree_hash(enum_behaviour = "transparent")
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadBid<E: EthSpec> {
    #[superstruct(getter(copy))]
    pub parent_block_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub parent_block_root: Hash256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub builder_index: u64,
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub value: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub execution_payment: u64,
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(getter(copy))]
    pub execution_requests_root: Hash256,
    #[superstruct(only(Heze))]
    pub inclusion_list_bits: BitVector<E::InclusionListCommitteeSize>,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadBidGloas<E> {}
impl<E: EthSpec> SignedRoot for ExecutionPayloadBidHeze<E> {}
impl<'a, E: EthSpec> SignedRoot for ExecutionPayloadBidRef<'a, E> {}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBidGloas<MainnetEthSpec>);
    ssz_and_tree_hash_tests!(ExecutionPayloadBidHeze<MainnetEthSpec>);
}
