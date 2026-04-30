use crate::execution::{ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadBidRef};
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(TestRandom, TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[educe(PartialEq, Hash)]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
pub struct SignedExecutionPayloadBidGloas<E: EthSpec> {
    pub message: ExecutionPayloadBidGloas<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBidGloas<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidGloas::default(),
            signature: Signature::empty(),
        }
    }
}

#[derive(TestRandom, TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[educe(PartialEq, Hash)]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
pub struct SignedExecutionPayloadBidHeze<E: EthSpec> {
    pub message: ExecutionPayloadBidHeze<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBidHeze<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBidHeze::default(),
            signature: Signature::empty(),
        }
    }
}

pub enum SignedExecutionPayloadBidRef<'a, E: EthSpec> {
    Gloas(&'a SignedExecutionPayloadBidGloas<E>),
    Heze(&'a SignedExecutionPayloadBidHeze<E>),
}

impl<'a, E: EthSpec> SignedExecutionPayloadBidRef<'a, E> {
    pub fn message(&self) -> ExecutionPayloadBidRef<'a, E> {
        match self {
            Self::Gloas(inner) => ExecutionPayloadBidRef::Gloas(&inner.message),
            Self::Heze(inner) => ExecutionPayloadBidRef::Heze(&inner.message),
        }
    }

    pub fn signature(&self) -> &'a Signature {
        match self {
            Self::Gloas(inner) => &inner.signature,
            Self::Heze(inner) => &inner.signature,
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
