use super::BeaconBlockHeader;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

/// Two conflicting proposals from the same proposer (validator).
///
/// Spec v0.5.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ProposerSlashing {
    pub proposer_index: u64,
    pub header_1: BeaconBlockHeader,
    pub header_2: BeaconBlockHeader,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(ProposerSlashing);
}
