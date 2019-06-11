use super::PublicKey;
use milagro_bls::AggregatePublicKey as RawAggregatePublicKey;
use serde_hex::encode as hex_encode;

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

    pub fn add(&mut self, public_key: &PublicKey) {
        self.0.add(public_key.as_raw())
    }

    /// Returns the underlying public key.
    pub fn as_raw(&self) -> &RawAggregatePublicKey {
        &self.0
    }

    /// Return a hex string representation of this key's bytes.
    #[cfg(test)]
    pub fn as_hex_string(&self) -> String {
        hex_encode(self.as_raw().as_bytes())
    }
}
