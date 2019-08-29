use super::{PublicKey, BLS_PUBLIC_KEY_BYTE_SIZE};
use milagro_bls::G1Point;

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
