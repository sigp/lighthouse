use crate::ForkName;
use crate::Spec;
use crate::execution::ExecutionPayloadBid;
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(TreeHash, Debug, Clone, Encode, Decode, Serialize, Deserialize, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#signedexecutionpayloadbid
pub struct SignedExecutionPayloadBid {
    pub message: ExecutionPayloadBid,
    pub signature: Signature,
}

impl SignedExecutionPayloadBid {
    pub fn epoch(&self) -> crate::Epoch {
        self.message.slot.epoch(Spec::slots_per_epoch())
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

    pub fn num_blobs_expected(&self) -> usize {
        self.message.blob_kzg_commitments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedExecutionPayloadBid);
}
