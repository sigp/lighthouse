use crate::{consts::altair::NUM_FLAG_INDICES, test_utils::TestRandom, Hash256};
use safe_arith::{ArithError, SafeArith};
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};
use test_random_derive::TestRandom;
use tree_hash::{TreeHash, TreeHashType};

#[derive(Debug, Default, Clone, Copy, PartialEq, Deserialize, Serialize, TestRandom)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct ParticipationFlags {
    #[serde(with = "eth2_serde_utils::quoted_u8")]
    bits: u8,
}

impl ParticipationFlags {
    pub fn add_flag(&mut self, flag_index: usize) -> Result<(), ArithError> {
        if flag_index >= NUM_FLAG_INDICES {
            return Err(ArithError::Overflow);
        }
        self.bits |= 1u8.safe_shl(flag_index as u32)?;
        Ok(())
    }

    pub fn has_flag(&self, flag_index: usize) -> Result<bool, ArithError> {
        if flag_index >= NUM_FLAG_INDICES {
            return Err(ArithError::Overflow);
        }
        let mask = 1u8.safe_shl(flag_index as u32)?;
        Ok(self.bits & mask == mask)
    }

    pub fn into_u8(self) -> u8 {
        self.bits
    }
}

/// Decode implementation that transparently behaves like the inner `u8`.
impl Decode for ParticipationFlags {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        u8::from_ssz_bytes(bytes).map(|bits| Self { bits })
    }
}

/// Encode implementation that transparently behaves like the inner `u8`.
impl Encode for ParticipationFlags {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.bits.ssz_append(buf);
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.bits.ssz_bytes_len()
    }

    fn as_ssz_bytes(&self) -> Vec<u8> {
        self.bits.as_ssz_bytes()
    }
}

impl TreeHash for ParticipationFlags {
    fn tree_hash_type() -> TreeHashType {
        u8::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.bits.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.bits.tree_hash_root()
    }
}
