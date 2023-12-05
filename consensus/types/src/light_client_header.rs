use crate::test_utils::TestRandom;
use crate::BeaconBlockHeader;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    arbitrary::Arbitrary,
)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
}

impl From<BeaconBlockHeader> for LightClientHeader {
    fn from(beacon: BeaconBlockHeader) -> Self {
        LightClientHeader { beacon }
    }
}
