use crate::{
    test_utils::TestRandom, ChainSpec, Domain, Epoch, Fork, Hash256, SecretKey, Signature,
    SignedRoot, SignedVoluntaryExit,
};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    pub validator_index: u64,
}

impl SignedRoot for VoluntaryExit {}

impl VoluntaryExit {
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedVoluntaryExit {
        let domain = spec.get_domain(
            self.epoch,
            Domain::VoluntaryExit,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = Signature::new(message.as_bytes(), &secret_key);
        SignedVoluntaryExit {
            message: self,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(VoluntaryExit);
}
