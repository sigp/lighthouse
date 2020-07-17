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

    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

/// A BLS aggregate public key that is generic across some BLS point (`AggPub`).
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to `AggPub`.
#[derive(Clone, PartialEq)]
pub struct AggregatePublicKey<AggPub> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: AggPub,
}

impl<AggPub> AggregatePublicKey<AggPub>
where
    AggPub: TAggregatePublicKey,
{
    /// Initialize `Self` to a "zero" value which can then have other public keys aggregated upon
    /// it.
    pub fn zero() -> Self {
        Self {
            point: AggPub::zero(),
        }
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
            point: AggPub::deserialize(bytes)?,
        })
    }
}

impl<AggPub: Eq> Eq for AggregatePublicKey<AggPub> {}

/// Hashes the `self.serialize()` bytes.
impl<AggPub: TAggregatePublicKey> Hash for AggregatePublicKey<AggPub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize()[..].hash(state);
    }
}

impl<AggPub: TAggregatePublicKey> Encode for AggregatePublicKey<AggPub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<AggPub: TAggregatePublicKey> Decode for AggregatePublicKey<AggPub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<AggPub: TAggregatePublicKey> TreeHash for AggregatePublicKey<AggPub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<AggPub: TAggregatePublicKey> Serialize for AggregatePublicKey<AggPub> {
    impl_serde_serialize!();
}

impl<'de, AggPub: TAggregatePublicKey> Deserialize<'de> for AggregatePublicKey<AggPub> {
    impl_serde_deserialize!();
}

impl<AggPub: TAggregatePublicKey> fmt::Debug for AggregatePublicKey<AggPub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<AggPub: TAggregatePublicKey + 'static> arbitrary::Arbitrary for AggregatePublicKey<AggPub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}
