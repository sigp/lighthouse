use crate::test_utils::TestRandom;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

// FIXME(altair): implement functions on this
#[derive(
    Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Encode, Decode, TreeHash, TestRandom,
)]
#[serde(transparent)]
pub struct ParticipationFlags {
    bits: u8,
}
