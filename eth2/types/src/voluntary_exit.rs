use crate::{test_utils::TestRandom, Epoch};
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.4.0
#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom, SignedRoot)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    pub validator_index: u64,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(VoluntaryExit);
}
