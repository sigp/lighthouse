use super::{PublicKey, BLS_PUBLIC_KEY_BYTE_SIZE};
use hex::encode as hex_encode;
use milagro_bls::G1Point;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::PrefixedHexVisitor;
use ssz::{ssz_encode, Decode, DecodeError, Encode};

/// A BLS aggregate public key.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Default)]
pub struct FakeAggregatePublicKey {
    bytes: Vec<u8>,
    /// Never used, only use for compatibility with "real" `AggregatePublicKey`.
    pub point: G1Point,
}

impl FakeAggregatePublicKey {
    pub fn new() -> Self {
        Self::zero()
    }

    pub fn empty_signature() -> Self {
        Self {
            bytes: vec![0; BLS_PUBLIC_KEY_BYTE_SIZE],
            point: G1Point::new(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != BLS_PUBLIC_KEY_BYTE_SIZE {
            Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: BLS_PUBLIC_KEY_BYTE_SIZE,
            })
        } else {
            Ok(Self {
                bytes: bytes.to_vec(),
                point: G1Point::new(),
            })
        }
    }

    pub fn add_without_affine(&mut self, _public_key: &PublicKey) {
        // No nothing.
    }

    pub fn affine(&mut self) {
        // No nothing.
    }

    /// Creates a new all-zero's aggregate public key
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_PUBLIC_KEY_BYTE_SIZE],
            point: G1Point::new(),
        }
    }

    pub fn add(&mut self, _public_key: &PublicKey) {
        // No nothing.
    }

    pub fn add_point(&mut self, _point: &G1Point) {
        // No nothing.
    }

    pub fn aggregate(_pks: &[&PublicKey]) -> Self {
        Self::new()
    }

    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self {
            bytes: public_key.as_bytes(),
            point: public_key.point.clone(),
        }
    }

    pub fn as_raw(&self) -> &Self {
        &self
    }

    pub fn into_raw(self) -> Self {
        self
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl_ssz!(
    FakeAggregatePublicKey,
    BLS_PUBLIC_KEY_BYTE_SIZE,
    "FakeAggregatePublicKey"
);

impl_tree_hash!(FakeAggregatePublicKey, BLS_PUBLIC_KEY_BYTE_SIZE);

impl Serialize for FakeAggregatePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for FakeAggregatePublicKey {
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
impl arbitrary::Arbitrary for FakeAggregatePublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BLS_PUBLIC_KEY_BYTE_SIZE];
        u.fill_buffer(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}
