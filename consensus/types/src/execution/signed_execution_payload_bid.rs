use crate::execution::ExecutionPayloadBid;
use crate::test_utils::TestRandom;
use crate::{EthSpec, ForkName, ForkVersionDecode};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz::Decode as _;
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
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#signedexecutionpayloadbid
pub struct SignedExecutionPayloadBid<E: EthSpec> {
    pub message: ExecutionPayloadBid<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedExecutionPayloadBid<E> {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBid::default(),
            signature: Signature::empty(),
        }
    }
}

impl<E: EthSpec> ForkVersionDecode for SignedExecutionPayloadBid<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        if !fork_name.gloas_enabled() {
            return Err(ssz::DecodeError::BytesInvalid(format!(
                "SignedExecutionPayloadBid is only defined for Gloas+; got {fork_name}",
            )));
        }
        Self::from_ssz_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBid<MainnetEthSpec>);
}
