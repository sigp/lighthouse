use lean_crypto::Signature;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use types::Hash256;

use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct Attestation {
    pub validator_id: u64,
    pub attestation_data: AttestationData,
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
pub struct AttestationData {
    pub slot: Slot,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Slot(pub u64);

impl Slot {
    pub fn is_justifiable_after(self, finalized_slot: Slot) -> Result<(), String> {
        if self <= finalized_slot {
            return Err(format!(
                "candidate slot must not be equal to or before finalized slot candidate={} finalized={}",
                self.0, finalized_slot.0
            ));
        }

        let delta = self.0 - finalized_slot.0;

        if delta >= 5
            && (delta.count_ones() == delta.trailing_ones() || {
                let val: u64 = 4 * delta + 1;
                val.count_ones() == val.trailing_ones()
                    && (delta.wrapping_sub(1) >> 2).count_ones()
                        == (delta.wrapping_sub(1) >> 2).trailing_ones()
            })
        {
            return Err(format!(
                "the slot is not justifiable after the finalized slot"
            ));
        }
        Ok(())
    }
}

impl TreeHash for Slot {
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

impl Encode for Slot {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for Slot {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u64::from_ssz_bytes(bytes).map(Slot)
    }
}

#[derive(Debug, Clone, Default, Encode, Decode, TreeHash)]
pub struct Checkpoint {
    pub root: Hash256,  // FIELD 0 - MUST MATCH SPEC ORDER
    pub slot: Slot,     // FIELD 1 - MUST MATCH SPEC ORDER
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedAttestation {
    pub message: Attestation,
    pub signature: Signature,
}
