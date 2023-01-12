use crate::{
    test_utils::TestRandom, BeaconBlockHeader, ChainSpec, Domain, EthSpec, Fork, Hash256,
    PublicKey, Signature, SignedRoot,
};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A signed header of a `BeaconBlock`.
///
/// Spec v0.12.1
#[derive(
    arbitrary::Arbitrary,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: Signature,
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
