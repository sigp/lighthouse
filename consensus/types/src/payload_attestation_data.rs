use crate::test_utils::TestRandom;
use crate::*;
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(
    arbitrary::Arbitrary,
    TestRandom,
    TreeHash,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    Hash,
)]
pub struct PayloadAttestationData {
    pub beacon_block_root: Hash256,
    pub slot: Slot,
    pub payload_status: PayloadStatus,
}

impl SignedRoot for PayloadAttestationData {}

#[repr(u8)]
#[derive(arbitrary::Arbitrary, Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum PayloadStatus {
    PayloadAbsent = 0,
    PayloadPresent = 1,
    PayloadWithheld = 2,
    PayloadInvalidStatus = 3,
}

impl TryFrom<u8> for PayloadStatus {
    type Error = String;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0 => Ok(PayloadStatus::PayloadAbsent),
            1 => Ok(PayloadStatus::PayloadPresent),
            2 => Ok(PayloadStatus::PayloadWithheld),
            3 => Ok(PayloadStatus::PayloadInvalidStatus),
            _ => Err(format!("Invalid byte for PayloadStatus: {}", byte)),
        }
    }
}

impl TestRandom for PayloadStatus {
    fn random_for_test(rng: &mut impl rand::RngCore) -> Self {
        rng.gen_range(0u8..=3u8)
            .try_into()
            .expect("PayloadStatus: random byte is valid")
    }
}

impl TreeHash for PayloadStatus {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        u8::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        (*self as u8).tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        (*self as u8).tree_hash_root()
    }
}

// ssz(enum_behaviour = "tag") would probably work but we want to ensure
// that the mapping between the variant and u8 matches the spec
impl Encode for PayloadStatus {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        <u8 as Encode>::ssz_bytes_len(&(*self as u8))
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        <u8 as Encode>::ssz_append(&(*self as u8), buf)
    }
}

impl Decode for PayloadStatus {
    fn is_ssz_fixed_len() -> bool {
        <u8 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u8 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        (*bytes
            // the u8 is just the first byte of the slice
            .get(0)
            .ok_or(ssz::DecodeError::InvalidByteLength {
                len: 0,
                expected: 1,
            })?)
        .try_into()
        .map_err(|s| ssz::DecodeError::BytesInvalid(s))
    }
}

impl Serialize for PayloadStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_utils::quoted_u8::Quoted::<u8>::serialize(
            &serde_utils::quoted_u8::Quoted {
                value: (*self as u8),
            },
            serializer,
        )
    }
}

impl<'de> Deserialize<'de> for PayloadStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let quoted = serde_utils::quoted_u8::Quoted::<u8>::deserialize(deserializer)?;
        PayloadStatus::try_from(quoted.value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod payload_attestation_data_tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadAttestationData);
}

#[cfg(test)]
mod payload_status_tests {
    use super::*;

    ssz_and_tree_hash_tests!(PayloadStatus);
}
