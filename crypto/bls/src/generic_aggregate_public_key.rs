use crate::{generic_public_key::GenericPublicKey, Error};
use std::marker::PhantomData;

/// Implemented on some struct from a BLS library so it may be used internally in this crate.
pub trait TAggregatePublicKey<Pub>: Sized + Clone {
    fn to_public_key(&self) -> GenericPublicKey<Pub>;

    // NOTE: this API *could* take a `&[&Pub]` as that's what the underlying library needs,
    // but it seems that this type would rarely occur due to our use of wrapper structs
    fn aggregate(pubkeys: &[GenericPublicKey<Pub>]) -> Result<Self, Error>;
}

/// A BLS aggregate public key that is generic across some BLS point (`AggPub`).
///
/// Provides generic functionality whilst deferring all serious cryptographic operations to `AggPub`.
#[derive(Clone)]
pub struct GenericAggregatePublicKey<Pub, AggPub> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: AggPub,
    _phantom: PhantomData<Pub>,
}

impl<Pub, AggPub> GenericAggregatePublicKey<Pub, AggPub>
where
    AggPub: TAggregatePublicKey<Pub>,
{
    pub fn to_public_key(&self) -> GenericPublicKey<Pub> {
        self.point.to_public_key()
    }

    pub fn aggregate(pubkeys: &[GenericPublicKey<Pub>]) -> Result<Self, Error> {
        Ok(Self {
            point: AggPub::aggregate(pubkeys)?,
            _phantom: PhantomData,
        })
    }
}
