use crate::{Error, PUBLIC_KEY_BYTES_LEN};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::fmt;
use std::hash::{Hash, Hasher};
use tree_hash::TreeHash;

/// Implemented on some struct from a BLS library so it may be used as the `point` in an
/// `AggregatePublicKey`.
pub trait TAggregatePublicKey: Sized + Clone {
    /// Initialize `Self` to a "zero" value which can then have other public keys aggregated upon
    /// it.
    fn zero() -> Self;

    /// Aggregates another `Self` onto `self`.
    fn add_assign(&mut self, other: &Self);

    /// Aggregates the `others` onto `self`.
    fn add_assign_multiple<'a>(&'a mut self, others: impl Iterator<Item = &'a Self>);

    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

/// A BLS aggregate public key that is generic across some BLS point (`Pub`).
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to `Pub`.
#[derive(Clone, PartialEq)]
pub struct AggregatePublicKey<Pub> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Pub,
}

impl<Pub> AggregatePublicKey<Pub>
where
    Pub: TAggregatePublicKey,
{
    /// Initialize `Self` to a "zero" value which can then have other public keys aggregated upon
    /// it.
    pub fn zero() -> Self {
        Self { point: Pub::zero() }
    }

    /// Aggregates another `Self` onto `self`.
    pub fn add_assign(&mut self, other: &Self) {
        self.point.add_assign(&other.point)
    }

    /// Aggregates the `others` onto `self`.
    pub fn add_assign_multiple<'a>(&'a mut self, others: impl Iterator<Item = &'a Self>) {
        self.point.add_assign_multiple(others.map(|pk| &pk.point))
    }

    /// Returns `self.serialize()` as a `0x`-prefixed hex string.
    pub fn to_hex_string(&self) -> String {
        format!("{:?}", self)
    }

    /// Serialize `self` as compressed bytes.
    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.point.serialize()
    }

    /// Deserialize `self` from compressed bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            point: Pub::deserialize(bytes)?,
        })
    }
}

impl<Pub: Eq> Eq for AggregatePublicKey<Pub> {}

/// Hashes the `self.serialize()` bytes.
impl<Pub: TAggregatePublicKey> Hash for AggregatePublicKey<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize()[..].hash(state);
    }
}

impl<Pub: TAggregatePublicKey> Encode for AggregatePublicKey<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TAggregatePublicKey> Decode for AggregatePublicKey<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TAggregatePublicKey> TreeHash for AggregatePublicKey<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TAggregatePublicKey> Serialize for AggregatePublicKey<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub: TAggregatePublicKey> Deserialize<'de> for AggregatePublicKey<Pub> {
    impl_serde_deserialize!();
}

impl<Pub: TAggregatePublicKey> fmt::Debug for AggregatePublicKey<Pub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: TAggregatePublicKey + 'static> arbitrary::Arbitrary for AggregatePublicKey<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}
