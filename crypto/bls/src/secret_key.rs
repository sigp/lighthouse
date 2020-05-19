extern crate rand;

use crate::PlainText;
use milagro_bls::SecretKey as RawSecretKey;
use ssz::DecodeError;

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Clone)]
pub struct SecretKey(RawSecretKey);

impl SecretKey {
    /// Generate a new `Self` using `rand::thread_rng`.
    pub fn random() -> Self {
        SecretKey(RawSecretKey::random(&mut rand::thread_rng()))
    }

    pub fn from_raw(raw: RawSecretKey) -> Self {
        Self(raw)
    }

    /// Returns the secret key as a byte array (wrapped in `PlainText` wrapper so it is zeroized on
    /// `Drop`).
    ///
    /// Extreme care should be taken not to leak these bytes as they are the unencrypted secret
    /// key.
    pub fn as_bytes(&self) -> PlainText {
        self.as_raw().as_bytes().into()
    }

    /// Instantiate a SecretKey from existing bytes.
    ///
    /// Note: this is _not_ SSZ decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, DecodeError> {
        Ok(SecretKey(RawSecretKey::from_bytes(bytes).map_err(|e| {
            DecodeError::BytesInvalid(format!(
                "Invalid SecretKey bytes: {:?} Error: {:?}",
                bytes, e
            ))
        })?))
    }

    /// Returns the underlying secret key.
    pub(crate) fn as_raw(&self) -> &RawSecretKey {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_ssz_round_trip() {
        let byte_key = [
            3, 211, 210, 129, 231, 69, 162, 234, 16, 15, 244, 214, 126, 201, 0, 85, 28, 239, 82,
            121, 208, 190, 223, 6, 169, 202, 86, 236, 197, 218, 3, 69,
        ];
        let original = SecretKey::from_bytes(&byte_key).unwrap();

        let bytes = original.as_bytes();
        let decoded = SecretKey::from_bytes(bytes.as_ref()).unwrap();

        assert!(original.as_bytes() == decoded.as_bytes());
    }
}
