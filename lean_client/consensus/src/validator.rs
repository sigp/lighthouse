use ssz_derive::{Decode, Encode};
use types::Hash256;
use tree_hash::TreeHash;
use crate::attestation::Slot;
use types::{FixedVector, typenum::U52};

use tree_hash_derive::TreeHash;
#[derive(Clone, PartialEq, Decode, Encode, TreeHash)]
pub struct Validator {
    pub pubkey: FixedVector<u8, U52>,
}

impl Validator {
    /// Get a reference to the public key bytes.
    pub fn get_pubkey(&self) -> &[u8] {
        &self.pubkey[..]
    }
}

pub struct ValidatorIndex(pub u64);
impl ValidatorIndex {
    pub fn is_proposer(&self, slot: Slot, num_validators: u64) -> bool {
        slot.0 % num_validators == self.0
    }
}


impl TreeHash for ValidatorIndex {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u64::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.0.tree_hash_root()
    }
}

