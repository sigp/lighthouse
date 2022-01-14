use crate::{
    generic_public_key::{GenericPublicKey, TPublicKey},
    Error, PUBLIC_KEY_BYTES_LEN,
};
use eth2_serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
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
pub struct GenericPublicKeyBytes<Pub> {
    bytes: [u8; PUBLIC_KEY_BYTES_LEN],
    _phantom: PhantomData<Pub>,
}

impl<Pub> Copy for GenericPublicKeyBytes<Pub> {}

impl<Pub> Clone for GenericPublicKeyBytes<Pub> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<Pub> GenericPublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    /// Decompress and deserialize the bytes in `self` into an actual public key.
    ///
    /// May fail if the bytes are invalid.
    pub fn decompress(&self) -> Result<GenericPublicKey<Pub>, Error> {
        GenericPublicKey::deserialize(&self.bytes)
    }
}

impl<Pub> GenericPublicKeyBytes<Pub> {
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
        self.bytes
    }

    /// Returns `self.serialize()` as a `0x`-prefixed hex string.
    pub fn as_hex_string(&self) -> String {
        format!("{:?}", self)
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

impl<Pub> Eq for GenericPublicKeyBytes<Pub> {}

impl<Pub> PartialEq for GenericPublicKeyBytes<Pub> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..] == other.bytes[..]
    }
}

impl<Pub> Hash for GenericPublicKeyBytes<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes[..].hash(state);
    }
}

/// Serializes the `PublicKey` in compressed form, storing the bytes in the newly created `Self`.
impl<Pub> From<GenericPublicKey<Pub>> for GenericPublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    fn from(pk: GenericPublicKey<Pub>) -> Self {
        Self::from(&pk)
    }
}

/// Serializes the `PublicKey` in compressed form, storing the bytes in the newly created `Self`.
impl<Pub> From<&GenericPublicKey<Pub>> for GenericPublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    fn from(pk: &GenericPublicKey<Pub>) -> Self {
        Self {
            bytes: pk.serialize(),
            _phantom: PhantomData,
        }
    }
}

/// Alias to `self.decompress()`.
impl<Pub> TryInto<GenericPublicKey<Pub>> for &GenericPublicKeyBytes<Pub>
where
    Pub: TPublicKey,
{
    type Error = Error;

    fn try_into(self) -> Result<GenericPublicKey<Pub>, Self::Error> {
        self.decompress()
    }
}

impl<Pub> Encode for GenericPublicKeyBytes<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> Decode for GenericPublicKeyBytes<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> TreeHash for GenericPublicKeyBytes<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub> fmt::Display for GenericPublicKeyBytes<Pub> {
    impl_display!();
}

impl<Pub> std::str::FromStr for GenericPublicKeyBytes<Pub> {
    impl_from_str!();
}

impl<Pub> Serialize for GenericPublicKeyBytes<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub> Deserialize<'de> for GenericPublicKeyBytes<Pub> {
    impl_serde_deserialize!();
}

impl<Pub> fmt::Debug for GenericPublicKeyBytes<Pub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: 'static> arbitrary::Arbitrary<'_> for GenericPublicKeyBytes<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}
