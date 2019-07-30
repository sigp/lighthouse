use std::cmp::min;
use std::fmt;

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use serde_hex::HexVisitor;
use ssz::{Decode, DecodeError, Encode, ssz_encode};

use super::{BLS_SIG_BYTE_SIZE, Signature};

#[derive(Clone)]
pub struct SignatureBytes([u8; BLS_SIG_BYTE_SIZE]);

impl SignatureBytes {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self::new_from_bytes(bytes))
    }

    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        Self(Self::get_bytes(bytes))
    }

    pub fn empty_signature() -> Self {
        Self::new_from_bytes(&[])
    }

    pub fn new(signature: Signature) -> Self {
        Self(Self::get_bytes(signature.as_bytes().as_slice()))
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn parse_signature(&self) -> Result<Signature, DecodeError> {
        Signature::from_bytes(&self.0[..])
    }

    fn get_bytes(bytes: &[u8]) -> [u8; BLS_SIG_BYTE_SIZE] {
        let mut signature_bytes = [0; BLS_SIG_BYTE_SIZE];
        let length = min(BLS_SIG_BYTE_SIZE, bytes.len());
        signature_bytes[..length].copy_from_slice(&bytes[..length]);
        signature_bytes
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

impl PartialEq for SignatureBytes {
    fn eq(&self, other: &Self) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl Eq for SignatureBytes {}

impl_ssz!(SignatureBytes, BLS_SIG_BYTE_SIZE, "Signature");

impl_tree_hash!(SignatureBytes, U96);

impl_cached_tree_hash!(SignatureBytes, U96);

impl Serialize for SignatureBytes {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&hex::encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    /// Serde serialization is compliant the Ethereum YAML test format.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(HexVisitor)?;
        let signature = Self::from_ssz_bytes(&bytes[..])
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //test parsing invalid signature
    #[test]
    pub fn test_invalid_signature() {
        let mut signature_bytes = [0; BLS_SIG_BYTE_SIZE];
        signature_bytes[0] = 255; //a_flag1 == b_flag1 == c_flag1 == 1 and x1 = 0 shouldn't be allowed
        let signature_bytes = SignatureBytes::from_bytes(&signature_bytes[..]);
        assert!(signature_bytes.is_ok());

        let signature = signature_bytes.unwrap().parse_signature();
        assert!(signature.is_err());
    }
}