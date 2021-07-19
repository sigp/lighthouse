use crate::{
    test_utils::TestRandom, BeaconBlockHeader, ChainSpec, Domain, EthSpec, Fork, Hash256,
    PublicKey, Signature, SignedRoot,
};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::hash::{Hash, Hasher};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A signed header of a `BeaconBlock`.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
    Derivative, Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom,
)]
#[derivative(PartialEq, Eq)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
}

/// Implementation of non-crypto-secure `Hash`, for use with `HashMap` and `HashSet`.
///
/// Guarantees `header1 == header2 -> hash(header1) == hash(header2)`.
///
/// Used in the slasher.
impl Hash for SignedBeaconBlockHeader {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.message.hash(state);
        self.signature.as_ssz_bytes().hash(state);
    }
}

impl SignedBeaconBlockHeader {
    /// Verify that this block header was signed by `pubkey`.
    pub fn verify_signature<E: EthSpec>(
        &self,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            self.message.slot.epoch(E::slots_per_epoch()),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );

        let message = self.message.signing_root(domain);

        self.signature.verify(pubkey, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(SignedBeaconBlockHeader);
}
