use super::PublicKey;
use bls_aggregates::AggregatePublicKey as RawAggregatePublicKey;

/// A single BLS signature.
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

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawAggregatePublicKey {
        &self.0
    }
}
