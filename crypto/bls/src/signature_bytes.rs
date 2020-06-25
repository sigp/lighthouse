use crate::{
    public_key::TPublicKey,
    signature::{Signature, TSignature},
    Error, SIGNATURE_BYTES_LEN,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

#[derive(Clone)]
pub struct SignatureBytes<Pub, Sig> {
    bytes: [u8; SIGNATURE_BYTES_LEN],
    _phantom_public_key: PhantomData<Pub>,
    _phantom_signature: PhantomData<Sig>,
}

impl<Pub, Sig> SignatureBytes<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
{
    pub fn decompress(&self) -> Result<Signature<Pub, Sig>, Error> {
        Sig::deserialize(&self.bytes).map(Signature::from_point)
    }
}

impl<Pub, Sig> SignatureBytes<Pub, Sig> {
    pub fn empty() -> Self {
        Self {
            bytes: [0; SIGNATURE_BYTES_LEN],
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
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

impl<Pub, Sig> PartialEq for SignatureBytes<Pub, Sig> {
    fn eq(&self, other: &Self) -> bool {
        &self.bytes[..] == &other.bytes[..]
    }
}

impl<Pub, Sig> From<Signature<Pub, Sig>> for SignatureBytes<Pub, Sig>
where
    Pub: TPublicKey,
    Sig: TSignature<Pub>,
{
    fn from(sig: Signature<Pub, Sig>) -> Self {
        Self {
            bytes: sig.serialize(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }
}

impl<Pub, Sig> Encode for SignatureBytes<Pub, Sig> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> Decode for SignatureBytes<Pub, Sig> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> TreeHash for SignatureBytes<Pub, Sig> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> Serialize for SignatureBytes<Pub, Sig> {
    impl_serde_serialize!();
}

impl<'de, Pub, Sig> Deserialize<'de> for SignatureBytes<Pub, Sig> {
    impl_serde_deserialize!();
}

impl<Pub, Sig> fmt::Debug for SignatureBytes<Pub, Sig> {
    impl_debug!();
}
