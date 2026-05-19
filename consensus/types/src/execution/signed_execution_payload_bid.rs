use crate::execution::ExecutionPayloadBid;
use crate::{EthSpec, ForkName};
use bls::Signature;
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, Educe)]
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
    pub fn epoch(&self) -> crate::Epoch {
        self.message.slot.epoch(E::slots_per_epoch())
    }

    pub fn slot(&self) -> crate::Slot {
        self.message.slot
    }

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
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBid<MainnetEthSpec>);
}
