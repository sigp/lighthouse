use super::{
    fake_aggregate_public_key::FakeAggregatePublicKey, fake_public_key::FakePublicKey,
    fake_signature::FakeSignature, BLS_AGG_SIG_BYTE_SIZE,
};
use milagro_bls::G2Point;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{ssz_encode, Decode, DecodeError, Encode};

/// A BLS aggregate signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Default, Eq)]
pub struct FakeAggregateSignature {
    bytes: Vec<u8>,
    /// Never used, only use for compatibility with "real" `AggregateSignature`.
    pub point: G2Point,
}

impl FakeAggregateSignature {
    /// Creates a new all-zero's signature
    pub fn new() -> Self {
        Self::zero()
    }

    /// Creates a new all-zero's signature
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_AGG_SIG_BYTE_SIZE],
            point: G2Point::new(),
        }
    }

    pub fn as_raw(&self) -> &Self {
        &self
    }

    /// Does glorious nothing.
    pub fn add(&mut self, _signature: &FakeSignature) {
        // Do nothing.
    }

    /// Does glorious nothing.
    pub fn add_aggregate(&mut self, _agg_sig: &FakeAggregateSignature) {
        // Do nothing.
    }

    /// Does glorious nothing.
    pub fn aggregate(&mut self, _agg_sig: &FakeAggregateSignature) {
        // Do nothing.
    }

    /// _Always_ returns `true`.
    pub fn verify(&self, _msg: &[u8], _aggregate_public_key: &FakeAggregatePublicKey) -> bool {
        true
    }

    /// _Always_ returns `true`.
    pub fn verify_multiple(
        &self,
        _messages: &[&[u8]],
        _aggregate_public_keys: &[&FakePublicKey],
    ) -> bool {
        true
    }

    /// _Always_ returns `true`.
    pub fn fast_aggregate_verify_pre_aggregated(
        &self,
        _messages: &[u8],
        _aggregate_public_keys: &FakeAggregatePublicKey,
    ) -> bool {
        true
    }

    /// _Always_ returns `true`.
    pub fn from_signature(signature: &FakeSignature) -> Self {
        Self {
            bytes: signature.as_bytes(),
            point: signature.point.clone(),
        }
    }

    /// Convert bytes to fake BLS aggregate signature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != BLS_AGG_SIG_BYTE_SIZE {
            Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: BLS_AGG_SIG_BYTE_SIZE,
            })
        } else {
            Ok(Self {
                bytes: bytes.to_vec(),
                point: G2Point::new(),
            })
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl_ssz!(
    FakeAggregateSignature,
    BLS_AGG_SIG_BYTE_SIZE,
    "FakeAggregateSignature"
);

impl_tree_hash!(FakeAggregateSignature, BLS_AGG_SIG_BYTE_SIZE);

impl Serialize for FakeAggregateSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for FakeAggregateSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let obj = <_>::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(obj)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary for FakeAggregateSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BLS_AGG_SIG_BYTE_SIZE];
        u.fill_buffer(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Keypair, Signature};
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let mut original = FakeAggregateSignature::new();
        original.add(&Signature::new(&[42, 42], &keypair.sk));

        let bytes = ssz_encode(&original);
        let decoded = FakeAggregateSignature::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
