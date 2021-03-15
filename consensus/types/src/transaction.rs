use crate::{test_utils::TestRandom, *};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

// TODO: move this into `EthSpec`.
pub type MaxBytesPerTransactionPayload = ssz_types::typenum::U1048576;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: Uint256,
    pub gas_limit: u64,
    pub recipient: Address,
    pub value: Uint256,
    pub input: VariableList<u8, MaxBytesPerTransactionPayload>,
    pub v: Uint256,
    pub r: Uint256,
    pub s: Uint256,
}
