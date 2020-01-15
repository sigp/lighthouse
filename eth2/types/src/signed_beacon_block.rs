use crate::{test_utils::TestRandom, BeaconBlock, EthSpec};
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;

/// An exit voluntarily submitted a validator who wishes to withdraw.
///
/// Spec v0.9.1
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
