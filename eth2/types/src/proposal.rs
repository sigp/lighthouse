use crate::test_utils::TestRandom;
use crate::{Hash256, Slot};
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// A proposal for some shard or beacon block.
///
/// Spec v0.4.0
#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom, SignedRoot)]
pub struct Proposal {
    pub slot: Slot,
    /// Shard number (spec.beacon_chain_shard_number for beacon chain)
    pub shard: u64,
    pub block_root: Hash256,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use ssz::{SignedRoot, TreeHash};

    #[derive(TreeHash)]
    struct SignedProposal {
        pub slot: Slot,
        pub shard: u64,
        pub block_root: Hash256,
    }

    impl Into<SignedProposal> for Proposal {
        fn into(self) -> SignedProposal {
            SignedProposal {
                slot: self.slot,
                shard: self.shard,
                block_root: self.block_root,
            }
        }
    }

    #[test]
    pub fn test_signed_root() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let original = Proposal::random_for_test(&mut rng);

        let other: SignedProposal = original.clone().into();

        assert_eq!(original.signed_root(), other.hash_tree_root());
    }

    ssz_tests!(Proposal);
}
