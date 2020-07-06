use crate::Error;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::fmt;
use std::hash::{Hash, Hasher};
use tree_hash::TreeHash;

pub const PUBLIC_KEY_BYTES_LEN: usize = 48;

pub trait TPublicKey: Sized + Clone {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Clone, PartialEq)]
pub struct PublicKey<Pub> {
    point: Pub,
}

impl<Pub> PublicKey<Pub>
where
    Pub: TPublicKey,
{
    pub(crate) fn from_point(point: Pub) -> Self {
        Self { point }
    }

    pub(crate) fn point(&self) -> &Pub {
        &self.point
    }

    pub fn to_hex_string(&self) -> String {
        format!("{:?}", self)
    }

    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.point.serialize()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            point: Pub::deserialize(bytes)?,
        })
    }
}

impl<Pub: Eq> Eq for PublicKey<Pub> {}

impl<Pub: TPublicKey> Hash for PublicKey<Pub> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialize()[..].hash(state);
    }
}

impl<Pub: TPublicKey> Encode for PublicKey<Pub> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> Decode for PublicKey<Pub> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> TreeHash for PublicKey<Pub> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}

impl<Pub: TPublicKey> Serialize for PublicKey<Pub> {
    impl_serde_serialize!();
}

impl<'de, Pub: TPublicKey> Deserialize<'de> for PublicKey<Pub> {
    impl_serde_deserialize!();
}

impl<Pub: TPublicKey> fmt::Debug for PublicKey<Pub> {
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub: TPublicKey + 'static> arbitrary::Arbitrary for PublicKey<Pub> {
    impl_arbitrary!(PUBLIC_KEY_BYTES_LEN);
}
