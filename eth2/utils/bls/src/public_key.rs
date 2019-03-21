use super::SecretKey;
use bls_aggregates::PublicKey as RawPublicKey;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{
    decode_ssz_list, hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash,
};
use std::default;
use std::hash::{Hash, Hasher};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Eq)]
pub struct PublicKey(RawPublicKey);

impl PublicKey {
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        PublicKey(RawPublicKey::from_secret_key(secret_key.as_raw()))
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawPublicKey {
        &self.0
    }

    /// Converts compressed bytes to PublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pubkey = RawPublicKey::from_bytes(&bytes).map_err(|_| DecodeError::Invalid)?;
        Ok(PublicKey(pubkey))
    }

    /// Returns the PublicKey as (x, y) bytes
    pub fn as_uncompressed_bytes(&self) -> Vec<u8> {
        RawPublicKey::as_uncompressed_bytes(&mut self.0.clone())
    }

    /// Converts (x, y) bytes to PublicKey
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pubkey =
            RawPublicKey::from_uncompressed_bytes(&bytes).map_err(|_| DecodeError::Invalid)?;
        Ok(PublicKey(pubkey))
    }

    /// Returns the last 6 bytes of the SSZ encoding of the public key, as a hex string.
    ///
    /// Useful for providing a short identifier to the user.
    pub fn concatenated_hex_id(&self) -> String {
        let bytes = ssz_encode(self);
        let end_bytes = &bytes[bytes.len().saturating_sub(6)..bytes.len()];
        hex_encode(end_bytes)
    }
}

impl default::Default for PublicKey {
    fn default() -> Self {
        let secret_key = SecretKey::random();
        PublicKey::from_secret_key(&secret_key)
    }
}

impl Encodable for PublicKey {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for PublicKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig = RawPublicKey::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((PublicKey(raw_sig), i))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_raw().as_bytes()))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let obj = PublicKey::from_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid pubkey ({:?})", e)))?;
        Ok(obj)
    }
}

impl TreeHash for PublicKey {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.0.as_bytes())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        ssz_encode(self) == ssz_encode(other)
    }
}

impl Hash for PublicKey {
    /// Note: this is distinct from consensus serialization, it will produce a different hash.
    ///
    /// This method uses the uncompressed bytes, which are much faster to obtain than the
    /// compressed bytes required for consensus serialization.
    ///
    /// Use `ssz::Encode` to obtain the bytes required for consensus hashing.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_uncompressed_bytes().hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let sk = SecretKey::random();
        let original = PublicKey::from_secret_key(&sk);

        let bytes = ssz_encode(&original);
        let (decoded, _) = PublicKey::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
