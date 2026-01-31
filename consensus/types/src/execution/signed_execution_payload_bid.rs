use crate::test_utils::TestRandom;
use crate::{ExecutionPayloadBid, ForkName};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[derive(TestRandom, TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[educe(PartialEq, Hash)]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#signedexecutionpayloadbid
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
    pub signature: Signature,
}

impl SignedExecutionPayloadBid {
    pub fn empty() -> Self {
        Self {
            message: ExecutionPayloadBid::default(),
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBid);
}
