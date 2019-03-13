use super::serde_vistors::HexVisitor;
use super::SecretKey;
use bls_aggregates::PublicKey as RawPublicKey;
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{
    decode_ssz_list, hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash,
};
use std::default;
use std::hash::{Hash, Hasher};

/// A single BLS public key.
///
/// This struct stores an uncompressed public key as a byte vec. The reason we store bytes instead
/// of the `RawPublicKey` struct is because it allows for building a hashmap of `PublicKey` much
/// faster.
///
/// Storing as uncompressed bytes costs ~0.02% more time when adding a `PublicKey` to an
/// `AggregateKey`, however it saves ~0.5ms each time you need to add a pubkey to a hashmap.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Eq)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        let mut raw_key = RawPublicKey::from_secret_key(secret_key.as_raw());
        let uncompressed_bytes = raw_key.as_uncompressed_bytes();
        Self {
            bytes: uncompressed_bytes,
        }
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> RawPublicKey {
        RawPublicKey::from_uncompressed_bytes(&self.bytes).expect("PublicKey in invalid state")
    }

    /// Converts compressed bytes to PublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut pubkey = RawPublicKey::from_bytes(&bytes).map_err(|_| DecodeError::Invalid)?;
        Ok(Self {
            bytes: pubkey.as_uncompressed_bytes(),
        })
    }

    /// Returns the PublicKey as (x, y) bytes
    pub fn as_uncompressed_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Converts (x, y) bytes to PublicKey
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // Do a conversion to check the bytes are valid.
        let _pubkey =
            RawPublicKey::from_uncompressed_bytes(&bytes).map_err(|_| DecodeError::Invalid)?;

        Ok(Self {
            bytes: bytes.to_vec(),
        })
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
        s.append_vec(&self.as_raw().as_bytes());
    }
}

impl Decodable for PublicKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let mut raw_sig =
            RawPublicKey::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;

        Ok((
            Self {
                bytes: raw_sig.as_uncompressed_bytes(),
            },
            i,
        ))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
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

impl TreeHash for PublicKey {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.as_raw().as_bytes())
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
        self.bytes.hash(state)
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
