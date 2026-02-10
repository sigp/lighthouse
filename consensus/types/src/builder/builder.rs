use crate::test_utils::TestRandom;
use crate::{Address, Epoch, ForkName};
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
