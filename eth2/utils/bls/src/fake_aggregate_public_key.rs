use super::{PublicKey, BLS_PUBLIC_KEY_BYTE_SIZE};

/// A BLS aggregate public key.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Default)]
pub struct FakeAggregatePublicKey {
    bytes: Vec<u8>,
}

impl FakeAggregatePublicKey {
    pub fn new() -> Self {
        Self::zero()
    }

    /// Creates a new all-zero's aggregate public key
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_PUBLIC_KEY_BYTE_SIZE],
        }
    }

    pub fn add(&mut self, _public_key: &PublicKey) {
        // No nothing.
    }

    pub fn as_raw(&self) -> &FakeAggregatePublicKey {
        &self
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}
