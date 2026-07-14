use crate::kzg_ext::KzgCommitments;
use crate::{
    Address, BeaconStateError, EthSpec, ExecutionBlockHash, ForkName, ForkVersionDecode, Hash256,
    SignedRoot, Slot,
};
use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::BitVector;
use superstruct::superstruct;
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
            Educe,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    ref_attributes(derive(Debug, PartialEq, TreeHash), tree_hash(enum_behaviour = "transparent")),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
// https://github.com/ethereum/consensus-specs/blob/master/specs/heze/beacon-chain.md#executionpayloadbid
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
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub value: u64,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub execution_payment: u64,
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(getter(copy))]
    pub execution_requests_root: Hash256,
    // [New in Heze:EIP7805]
    #[superstruct(only(Heze))]
    pub inclusion_list_bits: BitVector<E::InclusionListCommitteeSize>,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadBid<E> {}
impl<'a, E: EthSpec> SignedRoot for ExecutionPayloadBidRef<'a, E> {}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayloadBid<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Gloas => ExecutionPayloadBidGloas::from_ssz_bytes(bytes).map(Self::Gloas),
            ForkName::Heze => ExecutionPayloadBidHeze::from_ssz_bytes(bytes).map(Self::Heze),
            _ => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadBid: {fork_name}"
            ))),
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayloadBid<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "ExecutionPayloadBid failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            _ => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayloadBid failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
        })
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBidGloas<MainnetEthSpec>);
}

#[cfg(test)]
mod heze_tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBidHeze<MainnetEthSpec>);
}
