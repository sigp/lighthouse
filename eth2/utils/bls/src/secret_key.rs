use bls_aggregates::{DecodeError as BlsDecodeError, SecretKey as RawSecretKey};
use ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream, TreeHash};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct SecretKey(RawSecretKey);

impl SecretKey {
    pub fn random() -> Self {
        SecretKey(RawSecretKey::random())
    }

    /// Instantiate a SecretKey from existing bytes.
    ///
    /// Note: this is _not_ SSZ decoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, BlsDecodeError> {
        Ok(SecretKey(RawSecretKey::from_bytes(bytes)?))
    }

    /// Returns the underlying secret key.
    pub fn as_raw(&self) -> &RawSecretKey {
        &self.0
    }
}

impl Encodable for SecretKey {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for SecretKey {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig = RawSecretKey::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((SecretKey(raw_sig), i))
    }
}

impl TreeHash for SecretKey {
    fn hash_tree_root(&self) -> Vec<u8> {
        self.0.as_bytes().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;

    #[test]
    pub fn test_ssz_round_trip() {
        let original =
            SecretKey::from_bytes("jzjxxgjajfjrmgodszzsgqccmhnyvetcuxobhtynojtpdtbj".as_bytes())
                .unwrap();

        let bytes = ssz_encode(&original);
        let (decoded, _) = SecretKey::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
