use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

// TODO: move this into `EthSpec`.
pub type EvmBlockRootsSize = ssz_types::typenum::U8;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct BeaconChainData {
    pub slot: Slot,
    pub randao_mix: Hash256,
    pub timestamp: u64,
    pub recent_block_roots: FixedVector<Hash256, EvmBlockRootsSize>,
}
