use super::{fake_signature::FakeSignature, AggregatePublicKey};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{
    decode_ssz_list, hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash,
};

const SIGNATURE_LENGTH: usize = 48;

/// A BLS aggregate signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Default, Eq)]
pub struct FakeAggregateSignature {
    bytes: Vec<u8>,
}

impl FakeAggregateSignature {
    /// Creates a new all-zero's signature
    pub fn new() -> Self {
        Self::zero()
    }

    /// Creates a new all-zero's signature
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; SIGNATURE_LENGTH],
        }
    }

    /// Does glorious nothing.
    pub fn add(&mut self, _signature: &FakeSignature) {
        // Do nothing.
    }

    /// Does glorious nothing.
    pub fn add_aggregate(&mut self, _agg_sig: &FakeAggregateSignature) {
        // Do nothing.
    }

    /// _Always_ returns `true`.
    pub fn verify(
        &self,
        _msg: &[u8],
        _domain: u64,
        _aggregate_public_key: &AggregatePublicKey,
    ) -> bool {
        true
    }

    /// _Always_ returns `true`.
    pub fn verify_multiple(
        &self,
        _messages: &[&[u8]],
        _domain: u64,
        _aggregate_public_keys: &[&AggregatePublicKey],
    ) -> bool {
        true
    }
}

impl Encodable for FakeAggregateSignature {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.bytes);
    }
}

impl Decodable for FakeAggregateSignature {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        Ok((FakeAggregateSignature { bytes: sig_bytes }, i))
    }
}

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
        let (obj, _) = <_>::ssz_decode(&bytes[..], 0)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(obj)
    }
}

impl TreeHash for FakeAggregateSignature {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.bytes)
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
        original.add(&Signature::new(&[42, 42], 0, &keypair.sk));

        let bytes = ssz_encode(&original);
        let (decoded, _) = FakeAggregateSignature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
