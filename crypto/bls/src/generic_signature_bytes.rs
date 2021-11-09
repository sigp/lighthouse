use crate::{
    generic_public_key::TPublicKey,
    generic_signature::{GenericSignature, TSignature},
    Error, INFINITY_SIGNATURE, SIGNATURE_BYTES_LEN,
};
use eth2_serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{Decode, Encode};
use std::convert::TryInto;
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// A wrapper around some bytes that may or may not be a `GenericSignature` in compressed form.
///
/// This struct is useful for two things:
///
/// - Lazily verifying a serialized signature.
/// - Storing some bytes that are actually invalid (required in the case of a `Deposit` message).
#[derive(Clone)]
pub struct GenericSignatureBytes<Pub, Sig> {
    bytes: [u8; SIGNATURE_BYTES_LEN],
    _phantom_public_key: PhantomData<Pub>,
    _phantom_signature: PhantomData<Sig>,
}

impl<Pub, Sig> GenericSignatureBytes<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
{
    /// Decompress and deserialize the bytes in `self` into an actual signature.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<GenericSignature<Pub, Sig>, Error> {
        let is_infinity = self.bytes[..] == INFINITY_SIGNATURE[..];
        Sig::deserialize(&self.bytes).map(|point| GenericSignature::from_point(point, is_infinity))
    }
}

impl<Pub, Sig> GenericSignatureBytes<Pub, Sig> {
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
        self.bytes
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

impl<Pub, Sig> PartialEq for GenericSignatureBytes<Pub, Sig> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

/// Serializes the `GenericSignature` in compressed form, storing the bytes in the newly created `Self`.
impl<Pub, Sig> From<GenericSignature<Pub, Sig>> for GenericSignatureBytes<Pub, Sig>
where
    Pub: TPublicKey,
    Sig: TSignature<Pub>,
{
    fn from(sig: GenericSignature<Pub, Sig>) -> Self {
        Self {
            bytes: sig.serialize(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }
}

/// Alias to `self.decompress()`.
impl<Pub, Sig> TryInto<GenericSignature<Pub, Sig>> for &GenericSignatureBytes<Pub, Sig>
where
    Pub: TPublicKey,
    Sig: TSignature<Pub>,
{
    type Error = Error;

    fn try_into(self) -> Result<GenericSignature<Pub, Sig>, Error> {
        self.decompress()
    }
}

impl<Pub, Sig> Encode for GenericSignatureBytes<Pub, Sig> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> Decode for GenericSignatureBytes<Pub, Sig> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> TreeHash for GenericSignatureBytes<Pub, Sig> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<Pub, Sig> fmt::Display for GenericSignatureBytes<Pub, Sig> {
    impl_display!();
}

impl<Pub, Sig> std::str::FromStr for GenericSignatureBytes<Pub, Sig> {
    impl_from_str!();
}

impl<Pub, Sig> Serialize for GenericSignatureBytes<Pub, Sig> {
    impl_serde_serialize!();
}

impl<'de, Pub, Sig> Deserialize<'de> for GenericSignatureBytes<Pub, Sig> {
    impl_serde_deserialize!();
}

impl<Pub, Sig> fmt::Debug for GenericSignatureBytes<Pub, Sig> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: 'static, Sig: 'static> arbitrary::Arbitrary<'_> for GenericSignatureBytes<Pub, Sig> {
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}
