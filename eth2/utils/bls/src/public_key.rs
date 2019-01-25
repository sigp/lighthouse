use super::SecretKey;
use bls_aggregates::PublicKey as RawPublicKey;
use hex::encode as hex_encode;
use ssz::{decode_ssz_list, ssz_encode, Decodable, DecodeError, Encodable, SszStream};
use std::default;
use std::hash::{Hash, Hasher};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, Clone, Eq)]
pub struct PublicKey(RawPublicKey);

impl PublicKey {
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        PublicKey(RawPublicKey::from_secret_key(secret_key.as_raw()))
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawPublicKey {
        &self.0
    }

    /// Returns the last 6 bytes of the SSZ encoding of the public key, as a hex string.
    ///
    /// Useful for providing a short identifier to the user.
    pub fn concatenated_hex_id(&self) -> String {
        let bytes = ssz_encode(self);
        let end_bytes = &bytes[bytes.len().saturating_sub(6)..bytes.len()];
        hex_encode(end_bytes)
    }
}

impl default::Default for PublicKey {
    fn default() -> Self {
        let secret_key = SecretKey::random();
        PublicKey::from_secret_key(&secret_key)
    }
}

impl Encodable for PublicKey {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for PublicKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig = RawPublicKey::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((PublicKey(raw_sig), i))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        ssz_encode(self) == ssz_encode(other)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ssz_encode(self).hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::ssz::ssz_encode;
    use super::*;

    #[test]
    pub fn test_ssz_round_trip() {
        let sk = SecretKey::random();
        let original = PublicKey::from_secret_key(&sk);

        let bytes = ssz_encode(&original);
        let (decoded, _) = PublicKey::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
