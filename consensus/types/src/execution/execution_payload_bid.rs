use crate::kzg_ext::ProgressiveKzgCommitments;
use crate::{
    Address, BeaconStateError, ChainSpec, EthSpec, ExecutionBlockHash, ForkName, ForkVersionDecode,
    Hash256, InconsistentFork, SignedRoot, Slot,
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
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    ref_attributes(derive(Debug, PartialEq, TreeHash), tree_hash(enum_behaviour = "transparent")),
    specific_variant_attributes(
        Gloas(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        )),
        Heze(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        ))
    ),
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
#[derive(Debug, Clone, Serialize, Encode, TreeHash, Educe)]
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
    // [Modified in Gloas:EIP7688]
    pub blob_kzg_commitments: ProgressiveKzgCommitments<E>,
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
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadBid: {fork_name}"
            ))),
            ForkName::Gloas => ExecutionPayloadBidGloas::from_ssz_bytes(bytes).map(Self::Gloas),
            ForkName::Heze => ExecutionPayloadBidHeze::from_ssz_bytes(bytes).map(Self::Heze),
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
            ForkName::Base
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayloadBid failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

impl<'a, E: EthSpec> ExecutionPayloadBidRef<'a, E> {
    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_slot::<E>(self.slot());
        let object_fork = self.fork_name_unchecked();

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Returns the name of the fork pertaining to `self`.
    /// Does not check that the fork is consistent with the slot.
    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            ExecutionPayloadBidRef::Gloas(_) => ForkName::Gloas,
            ExecutionPayloadBidRef::Heze(_) => ForkName::Heze,
        }
    }
}

#[cfg(test)]
mod gloas_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBidGloas<Spec>);
}

#[cfg(test)]
mod heze_tests {
    use super::*;
    use crate::Spec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBidHeze<Spec>);

    #[test]
    fn inclusion_list_bits_committed_to_signing_root() {
        let bid = ExecutionPayloadBidHeze::<Spec>::default();
        let mut bid_with_bits = bid.clone();
        bid_with_bits
            .inclusion_list_bits
            .set(0, true)
            .expect("bit index should be within the committee size");

        let domain = Hash256::ZERO;
        assert_ne!(
            ExecutionPayloadBidRef::Heze(&bid).signing_root(domain),
            ExecutionPayloadBidRef::Heze(&bid_with_bits).signing_root(domain),
            "inclusion_list_bits must be covered by the Heze bid signing root",
        );
    }
}
