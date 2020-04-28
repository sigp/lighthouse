use super::*;
use milagro_bls::{AggregateSignature as RawAggregateSignature, G2Point};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, DecodeError, Encode};

/// A BLS aggregate signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Default, Eq)]
pub struct AggregateSignature {
    aggregate_signature: RawAggregateSignature,
    is_empty: bool,
}

impl AggregateSignature {
    /// Instantiate a new AggregateSignature.
    ///
    /// is_empty is false
    /// AggregateSignature is point at infinity
    pub fn new() -> Self {
        Self {
            aggregate_signature: RawAggregateSignature::new(),
            is_empty: false,
        }
    }

    /// Add (aggregate) a signature to the `AggregateSignature`.
    pub fn add(&mut self, signature: &Signature) {
        // Only empty if both are empty
        self.is_empty = self.is_empty && signature.is_empty();

        // Note: empty signatures will have point at infinity which is equivalent of adding 0.
        self.aggregate_signature.add(signature.as_raw())
    }

    /// Add (aggregate) another `AggregateSignature`.
    pub fn add_aggregate(&mut self, agg_signature: &AggregateSignature) {
        // Only empty if both are empty
        self.is_empty = self.is_empty && agg_signature.is_empty();

        // Note: empty signatures will have point at infinity which is equivalent of adding 0.
        self.aggregate_signature
            .add_aggregate(&agg_signature.aggregate_signature)
    }

    /// Verify the `AggregateSignature` against an `AggregatePublicKey`.
    ///
    /// Only returns `true` if the set of keys in the `AggregatePublicKey` match the set of keys
    /// that signed the `AggregateSignature`.
    pub fn verify(&self, msg: &[u8], aggregate_public_key: &AggregatePublicKey) -> bool {
        if self.is_empty {
            return false;
        }
        self.aggregate_signature
            .fast_aggregate_verify_pre_aggregated(msg, aggregate_public_key.as_raw())
    }

    /// Verify the `AggregateSignature` against an `AggregatePublicKey`.
    ///
    /// Only returns `true` if the set of keys in the `AggregatePublicKey` match the set of keys
    /// that signed the `AggregateSignature`.
    pub fn verify_unaggregated(&self, msg: &[u8], public_keys: &[&PublicKey]) -> bool {
        if self.is_empty {
            return false;
        }
        let public_key_refs: Vec<_> = public_keys.iter().map(|pk| pk.as_raw()).collect();
        self.aggregate_signature
            .fast_aggregate_verify(msg, &public_key_refs)
    }

    /// Verify this AggregateSignature against multiple AggregatePublickeys and Messages.
    ///
    /// Each AggregatePublicKey has a 1:1 ratio with a 32 byte Message.
    pub fn verify_multiple(&self, messages: &[&[u8]], public_keys: &[&PublicKey]) -> bool {
        if self.is_empty {
            return false;
        }
        let public_keys_refs: Vec<_> = public_keys.iter().map(|pk| pk.as_raw()).collect();
        self.aggregate_signature
            .aggregate_verify(&messages, &public_keys_refs)
    }

    /// Return AggregateSignature as bytes
    pub fn as_bytes(&self) -> Vec<u8> {
        if self.is_empty {
            return vec![0; BLS_AGG_SIG_BYTE_SIZE];
        }
        self.aggregate_signature.as_bytes()
    }

    /// Convert bytes to AggregateSignature
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        for byte in bytes {
            if *byte != 0 {
                let sig = RawAggregateSignature::from_bytes(&bytes).map_err(|_| {
                    DecodeError::BytesInvalid(format!(
                        "Invalid AggregateSignature bytes: {:?}",
                        bytes
                    ))
                })?;

                return Ok(Self {
                    aggregate_signature: sig,
                    is_empty: false,
                });
            }
        }
        Ok(Self::empty_signature())
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawAggregateSignature {
        &self.aggregate_signature
    }

    /// Returns the underlying signature.
    pub fn from_point(point: G2Point) -> Self {
        Self {
            aggregate_signature: RawAggregateSignature { point },
            is_empty: false,
        }
    }

    /// Returns if the AggregateSignature `is_empty`
    pub fn is_empty(&self) -> bool {
        self.is_empty
    }

    /// Creates a new AggregateSignature
    ///
    /// aggregate_signature set to the point infinity
    /// is_empty set to true
    pub fn empty_signature() -> Self {
        Self {
            aggregate_signature: RawAggregateSignature::new(),
            is_empty: true,
        }
    }

    /// Return a hex string representation of the bytes of this signature.
    #[cfg(test)]
    pub fn as_hex_string(&self) -> String {
        hex_encode(self.as_bytes())
    }
}

impl_ssz!(
    AggregateSignature,
    BLS_AGG_SIG_BYTE_SIZE,
    "AggregateSignature"
);

impl_tree_hash!(AggregateSignature, BLS_AGG_SIG_BYTE_SIZE);

impl Serialize for AggregateSignature {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for AggregateSignature {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let agg_sig = AggregateSignature::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;

        Ok(agg_sig)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary for AggregateSignature {
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
    use ssz::Encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let mut original = AggregateSignature::new();
        original.add(&Signature::new(&[42, 42], &keypair.sk));

        let bytes = original.as_ssz_bytes();
        let decoded = AggregateSignature::from_ssz_bytes(&bytes).unwrap();

        assert_eq!(original, decoded);
    }
}
