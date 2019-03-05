use super::Slot;
use crate::test_utils::TestRandom;
use bls::{PublicKey, Signature};
use rand::RngCore;
use serde_derive::Serialize;
use ssz::TreeHash;
use ssz_derive::{Decode, Encode, SignedRoot, TreeHash};
use test_random_derive::TestRandom;

/// The data submitted to the deposit contract.
///
/// Spec v0.4.0
#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom, SignedRoot)]
pub struct Transfer {
    pub from: u64,
    pub to: u64,
    pub amount: u64,
    pub fee: u64,
    pub slot: Slot,
    pub pubkey: PublicKey,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(Transfer);
}
