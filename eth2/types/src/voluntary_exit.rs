use crate::{test_utils::TestRandom, ChainSpec, Domain, Epoch, Fork};
use bls::{SecretKey, Signature};

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::{SignedRoot, TreeHash};
use tree_hash_derive::{SignedRoot, TreeHash};

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.9.1
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
)]
pub struct VoluntaryExit {
    /// Earliest epoch when voluntary exit can be processed.
    pub epoch: Epoch,
    pub validator_index: u64,
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

impl VoluntaryExit {
    /// Signs `self`.
    pub fn sign(&mut self, secret_key: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let message = self.signed_root();
        let domain = spec.get_domain(self.epoch, Domain::VoluntaryExit, &fork);
        self.signature = Signature::new(&message, domain, &secret_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(VoluntaryExit);
}
