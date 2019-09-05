use super::{SecretKey, BLS_PUBLIC_KEY_BYTE_SIZE};
use milagro_bls::G1Point;
use milagro_bls::PublicKey as RawPublicKey;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, HexVisitor};
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use std::default;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Eq)]
pub struct FakePublicKey {
    bytes: Vec<u8>,
    /// Never used, only use for compatibility with "real" `PublicKey`.
    pub point: G1Point,
}

impl FakePublicKey {
    pub fn from_secret_key(_secret_key: &SecretKey) -> Self {
        Self::zero()
    }

    pub fn from_raw(raw: RawPublicKey) -> Self {
        Self {
            bytes: raw.clone().as_bytes(),
            point: G1Point::new(),
        }
    }

    /// Creates a new all-zero's public key
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_PUBLIC_KEY_BYTE_SIZE],
            point: G1Point::new(),
        }
    }

    /// Returns the underlying point as compressed bytes.
    ///
    /// Identical to `self.as_uncompressed_bytes()`.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Converts compressed bytes to FakePublicKey
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            bytes: bytes.to_vec(),
            point: G1Point::new(),
        })
    }

    /// Returns the FakePublicKey as (x, y) bytes
    pub fn as_uncompressed_bytes(&self) -> Vec<u8> {
        self.as_bytes()
    }

    /// Converts (x, y) bytes to FakePublicKey
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::from_bytes(bytes)
    }

    /// Returns the last 6 bytes of the SSZ encoding of the public key, as a hex string.
    ///
    /// Useful for providing a short identifier to the user.
    pub fn concatenated_hex_id(&self) -> String {
        let bytes = ssz_encode(self);
        let end_bytes = &bytes[bytes.len().saturating_sub(6)..bytes.len()];
        hex_encode(end_bytes)
    }

    /// Returns the point as a hex string of the SSZ encoding.
    ///
    /// Note: the string is prefixed with `0x`.
    pub fn as_hex_string(&self) -> String {
        hex_encode(self.as_ssz_bytes())
    }

    // Returns itself
    pub fn as_raw(&self) -> &Self {
        self
    }
}

impl fmt::Display for FakePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.concatenated_hex_id())
    }
}

impl default::Default for FakePublicKey {
    fn default() -> Self {
        let secret_key = SecretKey::random();
        FakePublicKey::from_secret_key(&secret_key)
    }
}

impl_ssz!(FakePublicKey, BLS_PUBLIC_KEY_BYTE_SIZE, "FakePublicKey");

impl_tree_hash!(FakePublicKey, U48);

impl Serialize for FakePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for FakePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(HexVisitor)?;
        let pubkey = Self::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid pubkey ({:?})", e)))?;
        Ok(pubkey)
    }
}

impl PartialEq for FakePublicKey {
    fn eq(&self, other: &FakePublicKey) -> bool {
        ssz_encode(self) == ssz_encode(other)
    }
}

impl Hash for FakePublicKey {
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
        let original = FakePublicKey::from_secret_key(&sk);

        let bytes = ssz_encode(&original);
        let decoded = FakePublicKey::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
