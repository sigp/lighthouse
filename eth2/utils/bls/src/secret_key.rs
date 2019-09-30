extern crate rand;

use super::BLS_SECRET_KEY_BYTE_SIZE;
use hex::encode as hex_encode;
use milagro_bls::SecretKey as RawSecretKey;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::HexVisitor;
use ssz::{ssz_encode, Decode, DecodeError, Encode};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct SecretKey(RawSecretKey);

impl SecretKey {
    pub fn random() -> Self {
        SecretKey(RawSecretKey::random(&mut rand::thread_rng()))
    }

    pub fn from_raw(raw: RawSecretKey) -> Self {
        Self(raw)
    }

    /// Returns the underlying point as compressed bytes.
    fn as_bytes(&self) -> Vec<u8> {
        self.as_raw().as_bytes()
    }

    /// Instantiate a SecretKey from existing bytes.
    ///
    /// Note: this is _not_ SSZ decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, DecodeError> {
        Ok(SecretKey(RawSecretKey::from_bytes(bytes).map_err(|e| {
            DecodeError::BytesInvalid(format!(
                "Invalid SecretKey bytes: {:?} Error: {:?}",
                bytes, e
            ))
        })?))
    }

    /// Returns the underlying secret key.
    pub fn as_raw(&self) -> &RawSecretKey {
        &self.0
    }
}

impl_ssz!(SecretKey, BLS_SECRET_KEY_BYTE_SIZE, "SecretKey");

impl_tree_hash!(SecretKey, U48);

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(HexVisitor)?;
        let secret_key = SecretKey::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let original =
            SecretKey::from_bytes(b"jzjxxgjajfjrmgodszzsgqccmhnyvetcuxobhtynojtpdtbj").unwrap();

        let bytes = ssz_encode(&original);
        let decoded = SecretKey::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
