use crate::{
    generic_public_key::{GenericPublicKey, TPublicKey},
    Error, Hash256,
};
use eth2_serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{Decode, Encode};
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// The byte-length of a BLS signature when serialized in compressed form.
pub const SIGNATURE_BYTES_LEN: usize = 96;

/// Represents the signature at infinity.
pub const INFINITY_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [
    0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

/// The compressed bytes used to represent `GenericSignature::empty()`.
pub const NONE_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];

/// Implemented on some struct from a BLS library so it may be used as the `point` in an
/// `GenericSignature`.
pub trait TSignature<GenericPublicKey>: Sized + Clone {
    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;

    /// Returns `true` if `self` is a signature across `msg` by `pubkey`.
    fn verify(&self, pubkey: &GenericPublicKey, msg: Hash256) -> bool;
}

/// A BLS signature that is generic across:
///
/// - `Pub`: A BLS public key.
/// - `Sig`: A BLS signature.
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to the
/// generics.
#[derive(Clone, PartialEq, Eq)]
pub struct GenericSignature<Pub, Sig> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Option<Sig>,
    /// True if this point is equal to the `INFINITY_SIGNATURE`.
    pub(crate) is_infinity: bool,
    _phantom: PhantomData<Pub>,
}

impl<Pub, Sig> GenericSignature<Pub, Sig>
where
    Sig: TSignature<Pub>,
{
    /// Initialize self to the "empty" value. This value is serialized as all-zeros.
    ///
    /// ## Notes
    ///
    /// This function is not necessarily useful from a BLS cryptography perspective, it mostly
    /// exists to satisfy the Eth2 specification which expects the all-zeros serialization to be
    /// meaningful.
    pub fn empty() -> Self {
        Self {
            point: None,
            is_infinity: false,
            _phantom: PhantomData,
        }
    }

    /// Returns `true` if `self` is equal to the "empty" value.
    ///
    /// E.g., `Self::empty().is_empty() == true`
    pub fn is_empty(&self) -> bool {
        self.point.is_none()
    }

    /// Returns a reference to the underlying BLS point.
    pub(crate) fn point(&self) -> Option<&Sig> {
        self.point.as_ref()
    }

    /// Instantiates `Self` from a `point`.
    pub(crate) fn from_point(point: Sig, is_infinity: bool) -> Self {
        Self {
            point: Some(point),
            is_infinity,
            _phantom: PhantomData,
        }
    }

    /// Serialize `self` as compressed bytes.
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        if let Some(point) = &self.point {
            point.serialize()
        } else {
            NONE_SIGNATURE
        }
    }

    /// Deserialize `self` from compressed bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let point = if bytes == &NONE_SIGNATURE[..] {
            None
        } else {
            Some(Sig::deserialize(bytes)?)
        };

        Ok(Self {
            point,
            is_infinity: bytes == &INFINITY_SIGNATURE[..],
            _phantom: PhantomData,
        })
    }
}

impl<Pub, Sig> GenericSignature<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey + Clone,
{
    /// Returns `true` if `self` is a signature across `msg` by `pubkey`.
    pub fn verify(&self, pubkey: &GenericPublicKey<Pub>, msg: Hash256) -> bool {
        if let Some(point) = &self.point {
            point.verify(pubkey.point(), msg)
        } else {
            false
        }
    }
}

impl<PublicKey, T: TSignature<PublicKey>> Encode for GenericSignature<PublicKey, T> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Decode for GenericSignature<PublicKey, T> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> TreeHash for GenericSignature<PublicKey, T> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Display for GenericSignature<PublicKey, T> {
    impl_display!();
}

impl<PublicKey, T: TSignature<PublicKey>> std::str::FromStr for GenericSignature<PublicKey, T> {
    impl_from_str!();
}

impl<PublicKey, T: TSignature<PublicKey>> Serialize for GenericSignature<PublicKey, T> {
    impl_serde_serialize!();
}

impl<'de, PublicKey, T: TSignature<PublicKey>> Deserialize<'de> for GenericSignature<PublicKey, T> {
    impl_serde_deserialize!();
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Debug for GenericSignature<PublicKey, T> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<PublicKey: 'static, T: TSignature<PublicKey> + 'static> arbitrary::Arbitrary<'_>
    for GenericSignature<PublicKey, T>
{
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}
