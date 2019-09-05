use super::{PublicKey, SecretKey, BLS_SIG_BYTE_SIZE};
use hex::encode as hex_encode;
use milagro_bls::G2Point;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::HexVisitor;
use ssz::{ssz_encode, Decode, DecodeError, Encode};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct FakeSignature {
    bytes: Vec<u8>,
    is_empty: bool,
    /// Never used, only use for compatibility with "real" `Signature`.
    pub point: G2Point,
}

impl FakeSignature {
    /// Creates a new all-zero's signature
    pub fn new(_msg: &[u8], _domain: u64, _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// Creates a new all-zero's signature
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_SIG_BYTE_SIZE],
            is_empty: true,
            point: G2Point::new(),
        }
    }

    /// Creates a new all-zero's signature
    pub fn new_hashed(_x_real_hashed: &[u8], _x_imaginary_hashed: &[u8], _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// _Always_ returns `true`.
    pub fn verify(&self, _msg: &[u8], _domain: u64, _pk: &PublicKey) -> bool {
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
            Ok(Self {
                bytes: bytes.to_vec(),
                is_empty,
                point: G2Point::new(),
            })
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
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

impl_tree_hash!(FakeSignature, U96);

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
        let bytes = deserializer.deserialize_str(HexVisitor)?;
        let pubkey = <_>::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(pubkey)
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

        let original = FakeSignature::new(&[42, 42], 0, &keypair.sk);

        let bytes = ssz_encode(&original);
        let decoded = FakeSignature::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
