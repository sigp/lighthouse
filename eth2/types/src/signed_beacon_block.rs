use crate::{test_utils::TestRandom, BeaconBlock, EthSpec};
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

/// A `BeaconBlock` and a signature from its proposer.
///
/// Spec v0.10.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TestRandom)]
pub struct SignedBeaconBlock<E: EthSpec> {
    pub message: BeaconBlock<E>,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_tests!(SignedBeaconBlock<MainnetEthSpec>);
}
