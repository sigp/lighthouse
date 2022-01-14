use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_public_key::{GenericPublicKey, TPublicKey},
    generic_signature::{GenericSignature, TSignature},
    Error, Hash256, INFINITY_SIGNATURE, SIGNATURE_BYTES_LEN,
};
use eth2_serde_utils::hex::encode as hex_encode;
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use ssz::{Decode, Encode};
use std::fmt;
use std::marker::PhantomData;
use tree_hash::TreeHash;

/// The compressed bytes used to represent `GenericAggregateSignature::empty()`.
pub const EMPTY_SIGNATURE_SERIALIZATION: [u8; SIGNATURE_BYTES_LEN] = [0; SIGNATURE_BYTES_LEN];

/// Implemented on some struct from a BLS library so it may be used as the `point` in an
/// `GenericAggregateSignature`.
pub trait TAggregateSignature<Pub, AggPub, Sig>: Sized + Clone {
    /// Initialize `Self` to the infinity value which can then have other signatures aggregated
    /// upon it.
    fn infinity() -> Self;

    /// Aggregates a signature onto `self`.
    fn add_assign(&mut self, other: &Sig);

    /// Aggregates an aggregate signature onto `self`.
    fn add_assign_aggregate(&mut self, other: &Self);

    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN];

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;

    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed `msg`.
    fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&GenericPublicKey<Pub>]) -> bool;

    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed their
    /// corresponding message in `msgs`.
    ///
    /// ## Notes
    ///
    /// This function only exists for EF tests, it's presently not used in production.
    fn aggregate_verify(&self, msgs: &[Hash256], pubkeys: &[&GenericPublicKey<Pub>]) -> bool;
}

/// A BLS aggregate signature that is generic across:
///
/// - `Pub`: A BLS public key.
/// - `AggPub`: A BLS aggregate public key.
/// - `Sig`: A BLS signature.
/// - `AggSig`: A BLS aggregate signature.
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to the
/// generics.
#[derive(Clone, PartialEq)]
pub struct GenericAggregateSignature<Pub, AggPub, Sig, AggSig> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Option<AggSig>,
    /// True if this point is equal to the `INFINITY_SIGNATURE`.
    pub(crate) is_infinity: bool,
    _phantom_pub: PhantomData<Pub>,
    _phantom_agg_pub: PhantomData<AggPub>,
    _phantom_sig: PhantomData<Sig>,
}

impl<Pub, AggPub, Sig, AggSig> GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    /// Initialize `Self` to the infinity value which can then have other signatures aggregated
    /// upon it.
    pub fn infinity() -> Self {
        Self {
            point: Some(AggSig::infinity()),
            is_infinity: true,
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        }
    }

    /// Initialize self to the "empty" value. This value is serialized as all-zeros.
    ///
    /// This value can have another signature aggregated atop of it. When this happens, `self` is
    /// simply set to infinity before having the other signature aggregated onto it.
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
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        }
    }

    /// Returns `true` if `self` is equal to the "empty" value.
    ///
    /// E.g., `Self::empty().is_empty() == true`
    pub fn is_empty(&self) -> bool {
        self.point.is_none()
    }

    /// Returns `true` if `self` is equal to the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    /// Returns a reference to the underlying BLS point.
    pub(crate) fn point(&self) -> Option<&AggSig> {
        self.point.as_ref()
    }

    /// Aggregates a signature onto `self`.
    pub fn add_assign(&mut self, other: &GenericSignature<Pub, Sig>) {
        if let Some(other_point) = other.point() {
            self.is_infinity = self.is_infinity && other.is_infinity;
            if let Some(self_point) = &mut self.point {
                self_point.add_assign(other_point)
            } else {
                let mut self_point = AggSig::infinity();
                self_point.add_assign(other_point);
                self.point = Some(self_point)
            }
        }
    }

    /// Aggregates an aggregate signature onto `self`.
    pub fn add_assign_aggregate(&mut self, other: &Self) {
        if let Some(other_point) = other.point() {
            self.is_infinity = self.is_infinity && other.is_infinity;
            if let Some(self_point) = &mut self.point {
                self_point.add_assign_aggregate(other_point)
            } else {
                let mut self_point = AggSig::infinity();
                self_point.add_assign_aggregate(other_point);
                self.point = Some(self_point)
            }
        }
    }

    /// Serialize `self` as compressed bytes.
    pub fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        if let Some(point) = &self.point {
            point.serialize()
        } else {
            EMPTY_SIGNATURE_SERIALIZATION
        }
    }

    /// Deserialize `self` from compressed bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let point = if bytes == &EMPTY_SIGNATURE_SERIALIZATION[..] {
            None
        } else {
            Some(AggSig::deserialize(bytes)?)
        };

        Ok(Self {
            point,
            is_infinity: bytes == &INFINITY_SIGNATURE[..],
            _phantom_pub: PhantomData,
            _phantom_agg_pub: PhantomData,
            _phantom_sig: PhantomData,
        })
    }
}

impl<Pub, AggPub, Sig, AggSig> GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey<Pub> + Clone,
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed `msg`.
    pub fn fast_aggregate_verify(&self, msg: Hash256, pubkeys: &[&GenericPublicKey<Pub>]) -> bool {
        if pubkeys.is_empty() {
            return false;
        }

        match self.point.as_ref() {
            Some(point) => point.fast_aggregate_verify(msg, pubkeys),
            None => false,
        }
    }

    /// Wrapper for `fast_aggregate_verify` accepting `G2_POINT_AT_INFINITY` signature when
    /// `pubkeys` is empty.
    pub fn eth_fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&GenericPublicKey<Pub>],
    ) -> bool {
        if pubkeys.is_empty() && self.is_infinity() {
            true
        } else {
            self.fast_aggregate_verify(msg, pubkeys)
        }
    }

    /// Verify that `self` represents an aggregate signature where all `pubkeys` have signed their
    /// corresponding message in `msgs`.
    ///
    /// ## Notes
    ///
    /// This function only exists for EF tests, it's presently not used in production.
    pub fn aggregate_verify(&self, msgs: &[Hash256], pubkeys: &[&GenericPublicKey<Pub>]) -> bool {
        if msgs.is_empty() || msgs.len() != pubkeys.len() {
            return false;
        }

        match self.point.as_ref() {
            Some(point) => point.aggregate_verify(msgs, pubkeys),
            None => false,
        }
    }
}

/// Allow aggregate signatures to be created from single signatures.
impl<Pub, AggPub, Sig, AggSig> From<&GenericSignature<Pub, Sig>>
    for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    fn from(sig: &GenericSignature<Pub, Sig>) -> Self {
        let mut agg = Self::infinity();
        agg.add_assign(sig);
        agg
    }
}

impl<Pub, AggPub, Sig, AggSig> Encode for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_encode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> Decode for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_ssz_decode!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> TreeHash for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_tree_hash!(SIGNATURE_BYTES_LEN);
}

impl<Pub, AggPub, Sig, AggSig> fmt::Display for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_display!();
}

impl<Pub, AggPub, Sig, AggSig> std::str::FromStr
    for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_from_str!();
}

impl<Pub, AggPub, Sig, AggSig> Serialize for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_serialize!();
}

impl<'de, Pub, AggPub, Sig, AggSig> Deserialize<'de>
    for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_serde_deserialize!();
}

impl<Pub, AggPub, Sig, AggSig> fmt::Debug for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    impl_debug!();
}

#[cfg(feature = "arbitrary")]
impl<Pub, AggPub, Sig, AggSig> arbitrary::Arbitrary<'_>
    for GenericAggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: 'static,
    AggPub: 'static,
    Sig: TSignature<Pub> + 'static,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + 'static,
{
    impl_arbitrary!(SIGNATURE_BYTES_LEN);
}
