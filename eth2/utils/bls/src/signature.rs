use super::serde_vistors::HexVisitor;
use super::{PublicKey, SecretKey};
use bls_aggregates::Signature as RawSignature;
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{
    decode_ssz_list, hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash,
};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct Signature(RawSignature);

impl Signature {
    /// Instantiate a new Signature from a message and a SecretKey.
    pub fn new(msg: &[u8], domain: u64, sk: &SecretKey) -> Self {
        Signature(RawSignature::new(msg, domain, sk.as_raw()))
    }

    /// Instantiate a new Signature from a message and a SecretKey, where the message has already
    /// been hashed.
    pub fn new_hashed(x_real_hashed: &[u8], x_imaginary_hashed: &[u8], sk: &SecretKey) -> Self {
        Signature(RawSignature::new_hashed(
            x_real_hashed,
            x_imaginary_hashed,
            sk.as_raw(),
        ))
    }

    /// Verify the Signature against a PublicKey.
    pub fn verify(&self, msg: &[u8], domain: u64, pk: &PublicKey) -> bool {
        self.0.verify(msg, domain, &pk.as_raw())
    }

    /// Verify the Signature against a PublicKey, where the message has already been hashed.
    pub fn verify_hashed(
        &self,
        x_real_hashed: &[u8],
        x_imaginary_hashed: &[u8],
        pk: &PublicKey,
    ) -> bool {
        self.0
            .verify_hashed(x_real_hashed, x_imaginary_hashed, &pk.as_raw())
    }

    /// Returns the underlying signature.
    pub fn as_raw(&self) -> &RawSignature {
        &self.0
    }

    /// Returns a new empty signature.
    pub fn empty_signature() -> Self {
        // Empty Signature is currently being represented as BLS::Signature.point_at_infinity()
        // However it should be represented as vec![0; 96] but this
        // would require all signatures to be represented in byte form as opposed to Signature
        let mut empty: Vec<u8> = vec![0; 96];
        // Sets C_flag and B_flag to 1 and all else to 0
        empty[0] += u8::pow(2, 6) + u8::pow(2, 7);
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

impl TreeHash for Signature {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.0.as_bytes())
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(HexVisitor)?;
        let (pubkey, _) = <_>::ssz_decode(&bytes[..], 0)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(pubkey)
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

        let original = Signature::new(&[42, 42], 0, &keypair.sk);

        let bytes = ssz_encode(&original);
        let (decoded, _) = Signature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    pub fn test_empty_signature() {
        let sig = Signature::empty_signature();

        let sig_as_bytes: Vec<u8> = sig.as_raw().as_bytes();

        assert_eq!(sig_as_bytes.len(), 96);
        for (i, one_byte) in sig_as_bytes.iter().enumerate() {
            if i == 0 {
                assert_eq!(*one_byte, u8::pow(2, 6) + u8::pow(2, 7));
            } else {
                assert_eq!(*one_byte, 0);
            }
        }
    }
}
