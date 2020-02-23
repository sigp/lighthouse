use crate::{signature::TSignature, Error, SIGNATURE_BYTES_LEN};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

#[derive(Clone)]
pub struct SignatureBytes<Signature, PublicKey> {
    bytes: [u8; SIGNATURE_BYTES_LEN],
    _phantom_signature: PhantomData<Signature>,
    _phantom_public_key: PhantomData<PublicKey>,
}

impl<PublicKey, T: TSignature<PublicKey>> SignatureBytes<T, PublicKey> {
    pub fn decompress(&self) -> Result<T, Error> {
        T::deserialize(&self.bytes)
    }

    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.bytes.clone()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == SIGNATURE_BYTES_LEN {
            let mut pk_bytes = [0; SIGNATURE_BYTES_LEN];
            pk_bytes[..].copy_from_slice(bytes);
            Ok(Self {
                bytes: pk_bytes,
                _phantom_signature: PhantomData,
                _phantom_public_key: PhantomData,
            })
        } else {
            Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: SIGNATURE_BYTES_LEN,
            })
        }
    }
}

impl<Signature, PublicKey> PartialEq for SignatureBytes<Signature, PublicKey> {
    fn eq(&self, other: &Self) -> bool {
        &self.bytes[..] == &other.bytes[..]
    }
}

impl<PublicKey, T: TSignature<PublicKey>> Encode for SignatureBytes<T, PublicKey> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Decode for SignatureBytes<T, PublicKey> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> TreeHash for SignatureBytes<T, PublicKey> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Serialize for SignatureBytes<T, PublicKey> {
    impl_serde_serialize!();
}

impl<'de, PublicKey, T: TSignature<PublicKey>> Deserialize<'de> for SignatureBytes<T, PublicKey> {
    impl_serde_deserialize!();
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Debug for SignatureBytes<T, PublicKey> {
    impl_debug!();
}
