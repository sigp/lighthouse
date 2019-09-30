use super::Slot;
use crate::test_utils::TestRandom;
use bls::{PublicKey, Signature};
use derivative::Derivative;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{SignedRoot, TreeHash};

/// The data submitted to the deposit contract.
///
/// Spec v0.8.0
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    SignedRoot,
    Derivative,
)]
#[derivative(PartialEq, Eq, Hash)]
pub struct Transfer {
    pub sender: u64,
    pub recipient: u64,
    pub amount: u64,
    pub fee: u64,
    pub slot: Slot,
    pub pubkey: PublicKey,
    #[derivative(Hash = "ignore")]
    #[signed_root(skip_hashing)]
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Transfer);
}
