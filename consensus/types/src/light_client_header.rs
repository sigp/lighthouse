use super::{BeaconBlockHeader, SignedBlindedBeaconBlock};
use crate::{test_utils::TestRandom, EthSpec, Hash256, Slot};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

/// A LightClientHeader is a header that is verified by a light client.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom)]
pub struct LightClientHeader {
    // Beacon block header
    pub beacon: BeaconBlockHeader,
}

impl LightClientHeader {
    pub fn from_block<T: EthSpec>(block: &SignedBlindedBeaconBlock<T>) -> Self {
        Self {
            beacon: block.message().block_header(),
        }
    }

    pub fn zeros() -> Self {
        Self {
            beacon: BeaconBlockHeader {
                slot: Slot::new(0),
                proposer_index: 0,
                parent_root: Hash256::zero(),
                state_root: Hash256::zero(),
                body_root: Hash256::zero(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientHeader);
}
