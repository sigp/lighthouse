use crate::{
    aggregate_public_key::TAggregatePublicKey,
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Error, Hash256,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{Decode, Encode};
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const SIGNATURE_BYTES_LEN: usize = 96;
pub const NONE_SIGNATURE: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];

pub trait TAggregateSignature<Pub, AggPub, Sig>: Sized + Clone {
    fn zero() -> Self;

    fn add_assign(&mut self, other: &Sig);

    fn add_assign_aggregate(&mut self, other: &Self);

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;

    fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&PublicKey<Pub>]) -> bool;

    // Note: this only exists for tests.
    fn aggregate_verify(&self, msgs: &[Hash256], pubkeys: &[&PublicKey<Pub>]) -> bool;
}

#[derive(Clone, PartialEq)]
pub struct AggregateSignature<Pub, AggPub, Sig, AggSig> {
    point: Option<AggSig>,
    _phantom_pub: PhantomData<Pub>,
    _phantom_agg_pub: PhantomData<AggPub>,
    _phantom_sig: PhantomData<Sig>,
}

impl<Pub, AggPub, Sig, AggSig> AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    pub fn zero() -> Self {
        Self {
            point: Some(AggSig::zero()),
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        }
    }

    pub fn empty() -> Self {
        Self {
            point: None,
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.point.is_none()
    }

    pub(crate) fn point(&self) -> Option<&AggSig> {
        self.point.as_ref()
    }

    pub fn add_assign(&mut self, other: &Signature<Pub, Sig>) {
        match (&mut self.point, other.point()) {
            (Some(a), Some(b)) => a.add_assign(b),
            _ => {}
        }
    }

    pub fn add_assign_aggregate(&mut self, other: &Self) {
        match (&mut self.point, other.point()) {
            (Some(a), Some(b)) => a.add_assign_aggregate(b),
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
            Some(AggSig::deserialize(bytes)?)
        };

        Ok(Self {
            point,
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        })
    }
}

impl<Pub, AggPub, Sig, AggSig> AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey + Clone,
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    pub fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&PublicKey<Pub>]) -> bool {
        match self.point.as_ref() {
            Some(point) => point.fast_aggregate_verify(msg, pubkeys),
            None => false,
        }
    }

    pub fn aggregate_verify(&self, msgs: &[Hash256], pubkeys: &[&PublicKey<Pub>]) -> bool {
        match self.point.as_ref() {
            Some(point) => point.aggregate_verify(msgs, pubkeys),
            None => false,
        }
    }
}

impl<Pub, AggPub, Sig, AggSig> Encode for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> Decode for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> TreeHash for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> Serialize for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_serialize!();
}

impl<'de, Pub, AggPub, Sig, AggSig> Deserialize<'de>
    for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_deserialize!();
}

impl<Pub, AggPub, Sig, AggSig> fmt::Debug for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub, AggPub, Sig, AggSig> arbitrary::Arbitrary for AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: 'static,
    AggPub: 'static,
    Sig: TSignature<Pub> + 'static,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + 'static,
{
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}
