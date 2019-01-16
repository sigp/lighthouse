use super::SecretKey;
use bls_aggregates::PublicKey as RawPublicKey;
use ssz::{decode_ssz_list, ssz_encode, Decodable, DecodeError, Encodable, SszStream};
use std::hash::{Hash, Hasher};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct PublicKey(RawPublicKey);

impl PublicKey {
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        PublicKey(RawPublicKey::from_secret_key(secret_key.as_raw()))
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawPublicKey {
        &self.0
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

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        ssz_encode(self).hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
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
