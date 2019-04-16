use super::BLS_SECRET_KEY_BYTE_SIZE;
use bls_aggregates::{DecodeError as BlsDecodeError, SecretKey as RawSecretKey};
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::HexVisitor;
use ssz::{decode, ssz_encode, Decodable, DecodeError, Encodable, SszStream};
use tree_hash::impl_tree_hash_for_ssz_bytes;

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct SecretKey(RawSecretKey);

impl SecretKey {
    pub fn random() -> Self {
        SecretKey(RawSecretKey::random())
    }

    /// Instantiate a SecretKey from existing bytes.
    ///
    /// Note: this is _not_ SSZ decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, BlsDecodeError> {
        Ok(SecretKey(RawSecretKey::from_bytes(bytes)?))
    }

    /// Returns the underlying secret key.
    pub fn as_raw(&self) -> &RawSecretKey {
        &self.0
    }
}

impl Encodable for SecretKey {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(&self.0.as_bytes());
    }
}

impl Decodable for SecretKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        if bytes.len() - i < BLS_SECRET_KEY_BYTE_SIZE {
            return Err(DecodeError::TooShort);
        }
        let raw_sig = RawSecretKey::from_bytes(&bytes[i..(i + BLS_SECRET_KEY_BYTE_SIZE)])
            .map_err(|_| DecodeError::TooShort)?;
        Ok((SecretKey(raw_sig), i + BLS_SECRET_KEY_BYTE_SIZE))
    }
}

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
        let secret_key = decode::<SecretKey>(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(secret_key)
    }
}

impl_tree_hash_for_ssz_bytes!(SecretKey);

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let original =
            SecretKey::from_bytes("jzjxxgjajfjrmgodszzsgqccmhnyvetcuxobhtynojtpdtbj".as_bytes())
                .unwrap();

        let bytes = ssz_encode(&original);
        let (decoded, _) = SecretKey::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
