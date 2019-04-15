use crate::{test_utils::TestRandom, SlashableAttestation};
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Two conflicting attestations.
///
/// Spec v0.5.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct AttesterSlashing {
    pub slashable_attestation_1: SlashableAttestation,
    pub slashable_attestation_2: SlashableAttestation,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(AttesterSlashing);
}
