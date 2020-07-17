use crate::{
    public_key::TPublicKey,
    signature::{Signature, TSignature},
    Error, SIGNATURE_BYTES_LEN,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// A wrapper around some bytes that may or may not be a `Signature` in compressed form.
///
/// This struct is useful for two things:
///
/// - Lazily verifying a serialized signature.
/// - Storing some bytes that are actually invalid (required in the case of a `Deposit` message).
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
    /// Decompress and deserialize the bytes in `self` into an actual signature.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<Signature<Pub, Sig>, Error> {
        Sig::deserialize(&self.bytes).map(Signature::from_point)
    }
}

impl<Pub, Sig> SignatureBytes<Pub, Sig> {
    /// Instantiates `Self` with all-zeros.
    pub fn empty() -> Self {
        Self {
            bytes: [0; SIGNATURE_BYTES_LEN],
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }

    /// Clones the bytes in `self`.
    ///
    /// The bytes are not verified (i.e., they may not represent a valid BLS point).
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.bytes.clone()
    }

    /// Instantiates `Self` from bytes.
    ///
    /// The bytes are not fully verified (i.e., they may not represent a valid BLS point). Only the
    /// byte-length is checked.
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

/// Serializes the `Signature` in compressed form, storing the bytes in the newly created `Self`.
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

/// Alias to `self.decompress()`.
impl<Pub, Sig> TryInto<Signature<Pub, Sig>> for &SignatureBytes<Pub, Sig>
where
    Pub: TPublicKey,
    Sig: TSignature<Pub>,
{
    type Error = Error;

    fn try_into(self) -> Result<Signature<Pub, Sig>, Error> {
        self.decompress()
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

#[cfg(feature = "arbitrary")]
impl<Pub: 'static, Sig: 'static> arbitrary::Arbitrary for SignatureBytes<Pub, Sig> {
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}
