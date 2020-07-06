use super::{PublicKey, SecretKey, BLS_SIG_BYTE_SIZE};
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::PrefixedHexVisitor;
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use std::fmt;

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Clone)]
pub struct FakeSignature {
    bytes: [u8; BLS_SIG_BYTE_SIZE],
    is_empty: bool,
}

impl FakeSignature {
    /// Creates a new all-zero's signature
    pub fn new(_msg: &[u8], _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// Creates a new all-zero's signature
    pub fn zero() -> Self {
        Self {
            bytes: [0; BLS_SIG_BYTE_SIZE],
            is_empty: true,
        }
    }

    /// Creates a new all-zero's signature
    pub fn new_hashed(_x_real_hashed: &[u8], _x_imaginary_hashed: &[u8], _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// _Always_ returns `true`.
    pub fn verify(&self, _msg: &[u8], _pk: &PublicKey) -> bool {
        true
    }

    pub fn as_raw(&self) -> &Self {
        &self
    }

    /// _Always_ returns true.
    pub fn verify_hashed(
        &self,
        _x_real_hashed: &[u8],
        _x_imaginary_hashed: &[u8],
        _pk: &PublicKey,
    ) -> bool {
        true
    }

    /// Convert bytes to fake BLS Signature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != BLS_SIG_BYTE_SIZE {
            Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: BLS_SIG_BYTE_SIZE,
            })
        } else {
            let is_empty = bytes.iter().all(|x| *x == 0);
            let mut array = [0u8; BLS_SIG_BYTE_SIZE];
            array.copy_from_slice(bytes);
            Ok(Self {
                bytes: array,
                is_empty,
            })
        }
    }

    pub fn as_bytes(&self) -> [u8; BLS_SIG_BYTE_SIZE] {
        self.bytes.clone()
    }

    /// Returns a new empty signature.
    pub fn empty_signature() -> Self {
        FakeSignature::zero()
    }

    // Check for empty Signature
    pub fn is_empty(&self) -> bool {
        self.is_empty
    }
}

impl_ssz!(FakeSignature, BLS_SIG_BYTE_SIZE, "FakeSignature");

impl_tree_hash!(FakeSignature, BLS_SIG_BYTE_SIZE);

impl fmt::Debug for FakeSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{:?}, {:?}",
            self.bytes.to_vec(),
            self.is_empty()
        ))
    }
}

impl PartialEq for FakeSignature {
    fn eq(&self, other: &FakeSignature) -> bool {
        self.bytes.to_vec() == other.bytes.to_vec()
    }
}

impl Eq for FakeSignature {}

impl Serialize for FakeSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for FakeSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let pubkey = <_>::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(pubkey)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary for FakeSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BLS_SIG_BYTE_SIZE];
        u.fill_buffer(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Keypair;
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let original = FakeSignature::new(&[42, 42], &keypair.sk);

        let bytes = ssz_encode(&original);
        let decoded = FakeSignature::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
