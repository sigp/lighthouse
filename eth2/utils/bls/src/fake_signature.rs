use super::{PublicKey, SecretKey, BLS_SIG_BYTE_SIZE};
use hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::HexVisitor;
use ssz::{hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash};

/// A single BLS signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct FakeSignature {
    bytes: Vec<u8>,
}

impl FakeSignature {
    /// Creates a new all-zero's signature
    pub fn new(_msg: &[u8], _domain: u64, _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// Creates a new all-zero's signature
    pub fn zero() -> Self {
        Self {
            bytes: vec![0; BLS_SIG_BYTE_SIZE],
        }
    }

    /// Creates a new all-zero's signature
    pub fn new_hashed(_x_real_hashed: &[u8], _x_imaginary_hashed: &[u8], _sk: &SecretKey) -> Self {
        FakeSignature::zero()
    }

    /// _Always_ returns `true`.
    pub fn verify(&self, _msg: &[u8], _domain: u64, _pk: &PublicKey) -> bool {
        true
    }

    /// _Always_ returns true.
    pub fn verify_hashed(
        &self,
        _x_real_hashed: &[u8],
        _x_imaginary_hashed: &[u8],
        _pk: &PublicKey,
    ) -> bool {
        true
    }

    /// Returns a new empty signature.
    pub fn empty_signature() -> Self {
        FakeSignature::zero()
    }
}

impl Encodable for FakeSignature {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_encoded_raw(&self.bytes);
    }
}

impl Decodable for FakeSignature {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        if bytes.len() - i < BLS_SIG_BYTE_SIZE {
            return Err(DecodeError::TooShort);
        }
        Ok((
            FakeSignature {
                bytes: bytes[i..(i + BLS_SIG_BYTE_SIZE)].to_vec(),
            },
            i + BLS_SIG_BYTE_SIZE,
        ))
    }
}

impl TreeHash for FakeSignature {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.bytes)
    }
}

impl Serialize for FakeSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for FakeSignature {
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

        let original = FakeSignature::new(&[42, 42], 0, &keypair.sk);

        let bytes = ssz_encode(&original);
        let (decoded, _) = FakeSignature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
