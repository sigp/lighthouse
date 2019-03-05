use super::SlashableVoteData;
use crate::test_utils::TestRandom;
use rand::RngCore;
use serde_derive::Serialize;
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

#[derive(Debug, PartialEq, Clone, Serialize, Encode, Decode, TreeHash, TestRandom)]
pub struct CasperSlashing {
    pub slashable_vote_data_1: SlashableVoteData,
    pub slashable_vote_data_2: SlashableVoteData,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(CasperSlashing);
}
