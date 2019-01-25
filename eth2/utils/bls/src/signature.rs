use super::{PublicKey, SecretKey};
use bls_aggregates::Signature as RawSignature;
use ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct Signature(RawSignature);

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], sk: &SecretKey) -> Self {
        Signature(RawSignature::new(msg, sk.as_raw()))
    }

    /// Instantiate a new Signature from a message and a SecretKey, where the message has already
    /// been hashed.
    pub fn new_hashed(msg_hashed: &[u8], sk: &SecretKey) -> Self {
        Signature(RawSignature::new_hashed(msg_hashed, sk.as_raw()))
    }

    /// Verify the Signature against a PublicKey.
    pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> bool {
        self.0.verify(msg, pk.as_raw())
    }

    /// Verify the Signature against a PublicKey, where the message has already been hashed.
    pub fn verify_hashed(&self, msg_hash: &[u8], pk: &PublicKey) -> bool {
        self.0.verify_hashed(msg_hash, pk.as_raw())
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawSignature {
        &self.0
    }

    /// Returns a new empty signature.
    pub fn empty_signature() -> Self {
        let empty: Vec<u8> = vec![0; 97];
        Signature(RawSignature::from_bytes(&empty).unwrap())
    }
}

impl Encodable for Signature {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for Signature {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig = RawSignature::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((Signature(raw_sig), i))
    }
}

#[cfg(test)]
mod tests {
    use super::super::Keypair;
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let original = Signature::new(&[42, 42], &keypair.sk);

        let bytes = ssz_encode(&original);
        let (decoded, _) = Signature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_empty_signature() {
        let sig = Signature::empty_signature();

        let sig_as_bytes: Vec<u8> = sig.as_raw().as_bytes();

        assert_eq!(sig_as_bytes.len(), 97);
        for one_byte in sig_as_bytes.iter() {
            assert_eq!(*one_byte, 0);
        }
    }
}
