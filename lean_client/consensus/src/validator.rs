use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;
#[derive(Clone, PartialEq, Decode, Encode, TreeHash)]
pub struct Validator {}
