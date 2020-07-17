use crate::{
    public_key::{PublicKey, TPublicKey},
    Error, PUBLIC_KEY_BYTES_LEN,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// A wrapper around some bytes that may or may not be a `PublicKey` in compressed form.
///
/// This struct is useful for two things:
///
/// - Lazily verifying a serialized public key.
/// - Storing some bytes that are actually invalid (required in the case of a `Deposit` message).
#[derive(Clone)]
pub struct PublicKeyBytes<Pub> {
    bytes: [u8; PUBLIC_KEY_BYTES_LEN],
    _phantom: PhantomData<Pub>,
}

impl<Pub> PublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    /// Decompress and deserialize the bytes in `self` into an actual public key.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<PublicKey<Pub>, Error> {
        Pub::deserialize(&self.bytes).map(PublicKey::from_point)
    }
}

impl<Pub> PublicKeyBytes<Pub> {
    /// Instantiates `Self` with all-zeros.
    pub fn empty() -> Self {
        Self {
            bytes: [0; PUBLIC_KEY_BYTES_LEN],
            _phantom: PhantomData,
        }
    }

    /// Returns a slice of the bytes contained in `self`.
    ///
    /// The bytes are not verified (i.e., they may not represent a valid BLS point).
    pub fn as_serialized(&self) -> &[u8] {
        &self.bytes
    }

    /// Clones the bytes in `self`.
    ///
    /// The bytes are not verified (i.e., they may not represent a valid BLS point).
    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.bytes.clone()
    }

    /// Instantiates `Self` from bytes.
    ///
    /// The bytes are not fully verified (i.e., they may not represent a valid BLS point). Only the
    /// byte-length is checked.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == PUBLIC_KEY_BYTES_LEN {
            let mut pk_bytes = [0; PUBLIC_KEY_BYTES_LEN];
            pk_bytes[..].copy_from_slice(bytes);
            Ok(Self {
                bytes: pk_bytes,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_BYTES_LEN,
            })
        }
    }
}

impl<Pub> PartialEq for PublicKeyBytes<Pub> {
    fn eq(&self, other: &Self) -> bool {
        &self.bytes[..] == &other.bytes[..]
    }
}

impl<Pub> Eq for PublicKeyBytes<Pub> {}

impl<Pub> Hash for PublicKeyBytes<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

/// Serializes the `PublicKey` in compressed form, storing the bytes in the newly created `Self`.
impl<Pub> From<PublicKey<Pub>> for PublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    fn from(pk: PublicKey<Pub>) -> Self {
        Self {
            bytes: pk.serialize(),
            _phantom: PhantomData,
        }
    }
}

/// Alias to `self.decompress()`.
impl<Pub> TryInto<PublicKey<Pub>> for &PublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    type Error = Error;

    fn try_into(self) -> Result<PublicKey<Pub>, Self::Error> {
        self.decompress()
    }
}

impl<Pub> Encode for PublicKeyBytes<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> Decode for PublicKeyBytes<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> TreeHash for PublicKeyBytes<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> Serialize for PublicKeyBytes<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub> Deserialize<'de> for PublicKeyBytes<Pub> {
    impl_serde_deserialize!();
}

impl<Pub> fmt::Debug for PublicKeyBytes<Pub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: 'static> arbitrary::Arbitrary for PublicKeyBytes<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}
