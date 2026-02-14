use crate::test_utils::TestRandom;
use crate::{Address, ChainSpec, Epoch, ForkName};
use bls::PublicKeyBytes;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type BuilderIndex = u64;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, TestRandom, TreeHash,
)]
#[context_deserialize(ForkName)]
pub struct Builder {
    pub pubkey: PublicKeyBytes,
    #[serde(with = "serde_utils::quoted_u8")]
    pub version: u8,
    pub execution_address: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub balance: u64,
    pub deposit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

impl Builder {
    /// Check if a builder is active in a state with `finalized_epoch`.
    ///
    /// This implements `is_active_builder` from the spec.
    pub fn is_active_at_finalized_epoch(&self, finalized_epoch: Epoch, spec: &ChainSpec) -> bool {
        self.deposit_epoch < finalized_epoch && self.withdrawable_epoch == spec.far_future_epoch
    }
}
