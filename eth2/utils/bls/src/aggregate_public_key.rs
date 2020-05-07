use super::{PublicKey, BLS_PUBLIC_KEY_BYTE_SIZE};
use milagro_bls::AggregatePublicKey as RawAggregatePublicKey;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, DecodeError, Encode};

/// A BLS aggregate public key.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Default)]
pub struct AggregatePublicKey(RawAggregatePublicKey);

impl AggregatePublicKey {
    pub fn new() -> Self {
        AggregatePublicKey(RawAggregatePublicKey::new())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let pubkey = RawAggregatePublicKey::from_bytes(&bytes).map_err(|_| {
            DecodeError::BytesInvalid(format!("Invalid AggregatePublicKey bytes: {:?}", bytes))
        })?;

        Ok(AggregatePublicKey(pubkey))
    }

    pub fn add_without_affine(&mut self, public_key: &PublicKey) {
        self.0.point.add(&public_key.as_raw().point)
    }

    pub fn affine(&mut self) {
        self.0.point.affine()
    }

    pub fn add(&mut self, public_key: &PublicKey) {
        self.0.add(public_key.as_raw())
    }

    /// Returns the underlying public key.
    pub fn as_raw(&self) -> &RawAggregatePublicKey {
        &self.0
    }

    /// Returns the underlying point as compressed bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.as_raw().as_bytes()
    }

    pub fn into_raw(self) -> RawAggregatePublicKey {
        self.0
    }

    /// Return a hex string representation of this key's bytes.
    #[cfg(test)]
    pub fn as_hex_string(&self) -> String {
        serde_hex::encode(self.as_bytes())
    }
}

impl_ssz!(
    AggregatePublicKey,
    BLS_PUBLIC_KEY_BYTE_SIZE,
    "AggregatePublicKey"
);
impl_tree_hash!(AggregatePublicKey, BLS_PUBLIC_KEY_BYTE_SIZE);

impl Serialize for AggregatePublicKey {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for AggregatePublicKey {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let agg_sig = AggregatePublicKey::from_ssz_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;

        Ok(agg_sig)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary for AggregatePublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut bytes = [0u8; BLS_PUBLIC_KEY_BYTE_SIZE];
        u.fill_buffer(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}
