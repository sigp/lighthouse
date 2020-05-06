use crate::{
    test_utils::TestRandom, BeaconBlock, ChainSpec, Domain, EthSpec, Fork, Hash256, PublicKey,
    SignedRoot, SigningRoot, Slot,
};
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::fmt;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct SignedBeaconBlockHash(Hash256);

impl fmt::Debug for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedBeaconBlockHash({:?})", self.0)
    }
}

impl fmt::Display for SignedBeaconBlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for SignedBeaconBlockHash {
    fn from(hash: Hash256) -> SignedBeaconBlockHash {
        SignedBeaconBlockHash(hash)
    }
}

impl From<SignedBeaconBlockHash> for Hash256 {
    fn from(signed_beacon_block_hash: SignedBeaconBlockHash) -> Hash256 {
        signed_beacon_block_hash.0
    }
}

/// A `BeaconBlock` and a signature from its proposer.
///
/// Spec v0.11.1
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TestRandom)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBeaconBlock<E: EthSpec> {
    pub message: BeaconBlock<E>,
    pub signature: Signature,
}

impl<E: EthSpec> SignedBeaconBlock<E> {
    /// Verify `self.signature`.
    ///
    /// If the root of `block.message` is already known it can be passed in via `object_root_opt`.
    /// Otherwise, it will be computed locally.
    pub fn verify_signature(
        &self,
        object_root_opt: Option<Hash256>,
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

        let message = if let Some(object_root) = object_root_opt {
            SigningRoot {
                object_root,
                domain,
            }
            .tree_hash_root()
        } else {
            self.message.signing_root(domain)
        };

        self.signature.verify(message.as_bytes(), pubkey)
    }

    /// Convenience accessor for the block's slot.
    pub fn slot(&self) -> Slot {
        self.message.slot
    }

    /// Convenience accessor for the block's parent root.
    pub fn parent_root(&self) -> Hash256 {
        self.message.parent_root
    }

    /// Convenience accessor for the block's state root.
    pub fn state_root(&self) -> Hash256 {
        self.message.state_root
    }

    /// Returns the `tree_hash_root` of the block.
    ///
    /// Spec v0.11.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.message.tree_hash_root()[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(SignedBeaconBlock<MainnetEthSpec>);
}
