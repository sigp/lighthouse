use std::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use tree_hash::TreeHash;
use crate::test_utils::{RngCore, TestRandom};

const KZG_PROOF_BYTES_LEN: usize = 48;

#[derive(Debug, PartialEq, Hash, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KzgProof(#[serde(with = "serde_kzg_proof")] pub [u8; KZG_PROOF_BYTES_LEN]);

impl fmt::Display for KzgProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(&self.0))
    }
}

impl Default for KzgProof {
    fn default() -> Self {
        KzgProof([0; 48])
    }
}

impl From<[u8; KZG_PROOF_BYTES_LEN]> for KzgProof {
    fn from(bytes: [u8; KZG_PROOF_BYTES_LEN]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; KZG_PROOF_BYTES_LEN]> for KzgProof {
    fn into(self) -> [u8; KZG_PROOF_BYTES_LEN] {
        self.0
    }
}

pub mod serde_kzg_proof {
    use serde::de::Error;
    use super::*;

    pub fn serialize<S>(bytes: &[u8; KZG_PROOF_BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&eth2_serde_utils::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; KZG_PROOF_BYTES_LEN], D::Error>
        where
            D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;

        let bytes = eth2_serde_utils::hex::decode(&s).map_err(D::Error::custom)?;

        if bytes.len() != KZG_PROOF_BYTES_LEN {
            return Err(D::Error::custom(format!(
                "incorrect byte length {}, expected {}",
                bytes.len(),
                KZG_PROOF_BYTES_LEN
            )));
        }

        let mut array = [0; KZG_PROOF_BYTES_LEN];
        array[..].copy_from_slice(&bytes);

        Ok(array)
    }
}

impl Encode for KzgProof {
    fn is_ssz_fixed_len() -> bool {
        <[u8; KZG_PROOF_BYTES_LEN] as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <[u8; KZG_PROOF_BYTES_LEN] as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for KzgProof {
    fn is_ssz_fixed_len() -> bool {
        <[u8; KZG_PROOF_BYTES_LEN] as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <[u8; KZG_PROOF_BYTES_LEN] as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; KZG_PROOF_BYTES_LEN]>::from_ssz_bytes(bytes).map(Self)
    }
}

impl TreeHash for KzgProof {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; KZG_PROOF_BYTES_LEN]>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; KZG_PROOF_BYTES_LEN]>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for KzgProof {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0; KZG_PROOF_BYTES_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}
