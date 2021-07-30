use crate::{
    test_utils::{RngCore, TestRandom},
    Hash256,
};
use regex::bytes::Regex;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, DecodeError, Encode};
use std::fmt;
use std::str::FromStr;
use tree_hash::TreeHash;

pub const GRAFFITI_BYTES_LEN: usize = 32;

/// The 32-byte `graffiti` field on a beacon block.
#[derive(Default, Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
pub struct Graffiti(#[serde(with = "serde_graffiti")] pub [u8; GRAFFITI_BYTES_LEN]);

impl Graffiti {
    pub fn as_utf8_lossy(&self) -> String {
        #[allow(clippy::invalid_regex)] // This is a false positive, this regex is valid.
        let re = Regex::new("\\p{C}").expect("graffiti regex is valid");
        String::from_utf8_lossy(&re.replace_all(&self.0[..], &b""[..])).to_string()
    }
}

impl fmt::Display for Graffiti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", eth2_serde_utils::hex::encode(&self.0))
    }
}

impl From<[u8; GRAFFITI_BYTES_LEN]> for Graffiti {
    fn from(bytes: [u8; GRAFFITI_BYTES_LEN]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; GRAFFITI_BYTES_LEN]> for Graffiti {
    fn into(self) -> [u8; GRAFFITI_BYTES_LEN] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[serde(transparent)]
pub struct GraffitiString(String);

impl FromStr for GraffitiString {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().len() > GRAFFITI_BYTES_LEN {
            return Err(format!(
                "Graffiti exceeds max length {}",
                GRAFFITI_BYTES_LEN
            ));
        }
        Ok(Self(s.to_string()))
    }
}

impl<'de> Deserialize<'de> for GraffitiString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        GraffitiString::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Into<Graffiti> for GraffitiString {
    fn into(self) -> Graffiti {
        let graffiti_bytes = self.0.as_bytes();
        let mut graffiti = [0; GRAFFITI_BYTES_LEN];

        let graffiti_len = std::cmp::min(graffiti_bytes.len(), GRAFFITI_BYTES_LEN);

        // Copy the provided bytes over.
        //
        // Panic-free because `graffiti_bytes.len()` <= `GRAFFITI_BYTES_LEN`.
        graffiti
            .get_mut(..graffiti_len)
            .expect("graffiti_len <= GRAFFITI_BYTES_LEN")
            .copy_from_slice(graffiti_bytes);
        graffiti.into()
    }
}

pub mod serde_graffiti {
    use super::*;

    pub fn serialize<S>(bytes: &[u8; GRAFFITI_BYTES_LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&eth2_serde_utils::hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; GRAFFITI_BYTES_LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;

        let bytes = eth2_serde_utils::hex::decode(&s).map_err(D::Error::custom)?;

        if bytes.len() != GRAFFITI_BYTES_LEN {
            return Err(D::Error::custom(format!(
                "incorrect byte length {}, expected {}",
                bytes.len(),
                GRAFFITI_BYTES_LEN
            )));
        }

        let mut array = [0; GRAFFITI_BYTES_LEN];
        array[..].copy_from_slice(&bytes);

        Ok(array)
    }
}

impl Encode for Graffiti {
    fn is_ssz_fixed_len() -> bool {
        <[u8; GRAFFITI_BYTES_LEN] as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <[u8; GRAFFITI_BYTES_LEN] as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

impl Decode for Graffiti {
    fn is_ssz_fixed_len() -> bool {
        <[u8; GRAFFITI_BYTES_LEN] as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <[u8; GRAFFITI_BYTES_LEN] as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        <[u8; GRAFFITI_BYTES_LEN]>::from_ssz_bytes(bytes).map(Self)
    }
}

impl TreeHash for Graffiti {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <[u8; GRAFFITI_BYTES_LEN]>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <[u8; GRAFFITI_BYTES_LEN]>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}

impl TestRandom for Graffiti {
    fn random_for_test(rng: &mut impl RngCore) -> Self {
        Self::from(Hash256::random_for_test(rng).to_fixed_bytes())
    }
}
