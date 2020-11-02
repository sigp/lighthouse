use super::SECRET_KEY_BYTES_LEN;
use serde_derive::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Provides a wrapper around a `[u8; SECRET_KEY_BYTES_LEN]` that implements `Zeroize` on `Drop`.
#[derive(Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ZeroizeHash([u8; SECRET_KEY_BYTES_LEN]);

impl ZeroizeHash {
    /// Instantiates `Self` with all zeros.
    pub fn zero() -> Self {
        Self([0; SECRET_KEY_BYTES_LEN])
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

impl From<[u8; SECRET_KEY_BYTES_LEN]> for ZeroizeHash {
    fn from(array: [u8; SECRET_KEY_BYTES_LEN]) -> Self {
        Self(array)
    }
}

impl AsRef<[u8]> for ZeroizeHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
