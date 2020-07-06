use super::BLS_SECRET_KEY_BYTE_SIZE;
use zeroize::Zeroize;

/// Provides a wrapper around a `[u8; HASH_SIZE]` that implements `Zeroize` on `Drop`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretHash([u8; BLS_SECRET_KEY_BYTE_SIZE]);

impl SecretHash {
    /// Instantiates `Self` with all zeros.
    pub fn zero() -> Self {
        Self([0; BLS_SECRET_KEY_BYTE_SIZE])
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<[u8; BLS_SECRET_KEY_BYTE_SIZE]> for SecretHash {
    fn from(array: [u8; BLS_SECRET_KEY_BYTE_SIZE]) -> Self {
        Self(array)
    }
}

impl AsRef<[u8]> for SecretHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
