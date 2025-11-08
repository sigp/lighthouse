use ssz_derive::{Decode, Encode};
use types::{FixedVector, typenum::U52};

use tree_hash_derive::TreeHash;
#[derive(Clone, PartialEq, Decode, Encode, TreeHash)]
pub struct Validator {
    pubkey: FixedVector<u8, U52>,
}
