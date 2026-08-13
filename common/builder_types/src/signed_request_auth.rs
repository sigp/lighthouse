use crate::{RequestAuth, RequestAuthData};
use bls::Signature;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
use types::{ForkName, Slot};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct SignedRequestAuth {
    pub message: RequestAuth,
    pub signature: Signature,
}

impl SignedRequestAuth {
    /// An auth with zero-length `data`, slot `0`, and an all-zero signature.
    pub fn unset() -> Self {
        Self {
            message: RequestAuth {
                data: RequestAuthData::default(),
                slot: Slot::new(0),
            },
            signature: Signature::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedRequestAuth);
}
