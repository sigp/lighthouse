use super::ProposalSignedData;
use crate::test_utils::TestRandom;
use bls::Signature;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

mod builder;

pub use builder::ProposerSlashingBuilder;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct ProposerSlashing {
    pub proposer_index: u64,
    pub proposal_data_1: ProposalSignedData,
    pub proposal_signature_1: Signature,
    pub proposal_data_2: ProposalSignedData,
    pub proposal_signature_2: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(ProposerSlashing);
}
