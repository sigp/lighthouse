use crate::execution::{
    ExecutionPayloadBid, ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadBidRef,
};
use crate::state::BeaconStateError;
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Gloas, Heze),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TestRandom,
            TreeHash,
            Educe,
        ),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        context_deserialize(ForkName),
        serde(bound = "E: EthSpec"),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    map_ref_into(ExecutionPayloadBidRef)
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct SignedExecutionPayloadBid<E: EthSpec> {
    #[superstruct(flatten)]
    pub message: ExecutionPayloadBid<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBid<E> {
    pub fn message(&self) -> ExecutionPayloadBidRef<'_, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadBidRef::Heze(&inner.message),
        }
    }

    pub fn empty_gloas() -> Self {
        Self::Gloas(SignedExecutionPayloadBidGloas {
            message: ExecutionPayloadBidGloas::default(),
            signature: Signature::empty(),
        })
    }

    pub fn empty_heze() -> Self {
        Self::Heze(SignedExecutionPayloadBidHeze {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        })
    }
}

impl<'a, E: EthSpec> SignedExecutionPayloadBidRef<'a, E> {
    pub fn message(&self) -> ExecutionPayloadBidRef<'a, E> {
        map_signed_execution_payload_bid_ref_into_execution_payload_bid_ref!(
            &'a _,
            *self,
            |inner, cons| { cons(&inner.message) }
        )
    }
}

impl<E: EthSpec> SignedExecutionPayloadBidGloas<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidGloas::default(),
            signature: Signature::empty(),
        }
    }
}

impl<E: EthSpec> SignedExecutionPayloadBidHeze<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidGloas<MainnetEthSpec>);
    ssz_and_tree_hash_tests!(SignedExecutionPayloadBidHeze<MainnetEthSpec>);
}
