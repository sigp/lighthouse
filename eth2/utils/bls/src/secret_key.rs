use super::serde_vistors::HexVisitor;
use bls_aggregates::{DecodeError as BlsDecodeError, SecretKey as RawSecretKey};
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{decode_ssz_list, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};

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
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for SecretKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig = RawSecretKey::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((SecretKey(raw_sig), i))
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
        let (pubkey, _) = <_>::ssz_decode(&bytes[..], 0)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(pubkey)
    }
}

impl TreeHash for SecretKey {
    fn hash_tree_root(&self) -> Vec<u8> {
        self.0.as_bytes().clone()
    }
}

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
