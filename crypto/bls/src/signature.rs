use crate::{
    public_key::{PublicKey, TPublicKey},
    Error, Hash256,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const SIGNATURE_BYTES_LEN: usize = 96;
pub const NONE_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];

pub trait TSignature<PublicKey>: Sized {
    fn zero() -> Self;

    fn add_assign(&mut self, other: &Self);

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;

    fn verify(&self, pubkey: &PublicKey, msg: Hash256) -> bool;

    fn fast_aggregate_verify(&self, pubkeys: &[PublicKey], msgs: &[Hash256]) -> bool;
}

#[derive(Clone, PartialEq)]
pub struct Signature<Pub, Sig> {
    point: Option<Sig>,
    _phantom: PhantomData<Pub>,
}

impl<Pub, Sig> Signature<Pub, Sig>
where
    Sig: TSignature<Pub>,
{
    pub fn zero() -> Self {
        Self {
            point: Some(Sig::zero()),
            _phantom: PhantomData,
        }
    }

    pub fn none() -> Self {
        Self {
            point: None,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn from_point(point: Sig) -> Self {
        Self {
            point: Some(point),
            _phantom: PhantomData,
        }
    }

    pub(crate) fn point(&self) -> Option<&Sig> {
        self.point.as_ref()
    }

    pub fn add_assign(&mut self, other: &Self) {
        match (&mut self.point, &other.point) {
            (Some(a), Some(b)) => a.add_assign(b),
            _ => {}
        }
    }

    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        if let Some(point) = &self.point {
            point.serialize()
        } else {
            NONE_SIGNATURE
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let point = if bytes == &NONE_SIGNATURE[..] {
            None
        } else {
            Some(Sig::deserialize(bytes)?)
        };

        Ok(Self {
            point,
            _phantom: PhantomData,
        })
    }
}

impl<Pub, Sig> Signature<Pub, Sig>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey + Clone,
{
    pub fn verify(&self, pubkey: &PublicKey<Pub>, msg: Hash256) -> bool {
        if let Some(point) = &self.point {
            point.verify(pubkey.point(), msg)
        } else {
            false
        }
    }

    pub fn fast_aggregate_verify<'a>(
        &'a self,
        signed_messages: impl Iterator<Item = (Cow<'a, PublicKey<Pub>>, Hash256)>,
    ) -> bool {
        if let Some(point) = &self.point {
            let (pubkeys, msgs): (Vec<_>, Vec<_>) = signed_messages
                .into_iter()
                .map(|(pubkey, msg)| (pubkey.point().clone(), msg))
                .unzip();

            point.fast_aggregate_verify(&pubkeys[..], &msgs)
        } else {
            false
        }
    }
}

impl<PublicKey, T: TSignature<PublicKey>> Encode for Signature<PublicKey, T> {
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Decode for Signature<PublicKey, T> {
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> TreeHash for Signature<PublicKey, T> {
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<PublicKey, T: TSignature<PublicKey>> Serialize for Signature<PublicKey, T> {
    impl_serde_serialize!();
}

impl<'de, PublicKey, T: TSignature<PublicKey>> Deserialize<'de> for Signature<PublicKey, T> {
    impl_serde_deserialize!();
}

impl<PublicKey, T: TSignature<PublicKey>> fmt::Debug for Signature<PublicKey, T> {
    impl_debug!();
}
