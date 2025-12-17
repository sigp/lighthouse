use crate::attestation::Slot;
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use ssz_types::typenum::U52;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use types::Hash256;
#[derive(Clone, PartialEq, Decode, Encode, TreeHash, Debug)]
pub struct Validator {
    pub pubkey: FixedVector<u8, U52>,
    pub index: u64, // Added to match the Validator struct
}

impl Validator {
    /// Get a reference to the public key bytes.
    pub fn get_pubkey(&self) -> &[u8] {
        &self.pubkey[..]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ValidatorIndex(pub u64);

impl ssz::Encode for ValidatorIndex {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl ssz::Decode for ValidatorIndex {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u64::from_ssz_bytes(bytes).map(ValidatorIndex)
    }
}

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
