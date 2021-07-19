use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::{GenericAggregateSignature, TAggregateSignature},
    generic_public_key::{GenericPublicKey, TPublicKey},
    generic_signature::{GenericSignature, TSignature},
    Hash256,
};
use std::borrow::Cow;
use std::marker::PhantomData;

/// A generic way to represent a `GenericSignature` or `GenericAggregateSignature`.
pub struct WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    aggregate: Cow<'a, GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>,
}

impl<'a, Pub, AggPub, Sig, AggSig> From<&'a GenericSignature<Pub, Sig>>
    for WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    fn from(sig: &'a GenericSignature<Pub, Sig>) -> Self {
        let mut aggregate: GenericAggregateSignature<Pub, AggPub, Sig, AggSig> =
            GenericAggregateSignature::infinity();
        aggregate.add_assign(sig);
        WrappedSignature {
            aggregate: Cow::Owned(aggregate),
        }
    }
}

impl<'a, Pub, AggPub, Sig, AggSig> From<&'a GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>
    for WrappedSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    fn from(aggregate: &'a GenericAggregateSignature<Pub, AggPub, Sig, AggSig>) -> Self {
        WrappedSignature {
            aggregate: Cow::Borrowed(aggregate),
        }
    }
}

/// A generic way to represent a signature across a message by multiple public keys.
///
/// This struct is primarily useful in a collection (e.g., `Vec<GenericSignatureSet>`) so we can perform
/// multiple-signature verification which is much faster than verifying each signature
/// individually.
#[derive(Clone)]
pub struct GenericSignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    pub signature: Cow<'a, GenericAggregateSignature<Pub, AggPub, Sig, AggSig>>,
    pub(crate) signing_keys: Vec<Cow<'a, GenericPublicKey<Pub>>>,
    pub(crate) message: Hash256,
    _phantom: PhantomData<Sig>,
}

impl<'a, Pub, AggPub, Sig, AggSig> GenericSignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey<Pub> + Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    /// Instantiate self where `signature` is only signed by a single public key.
    pub fn single_pubkey(
        signature: impl Into<WrappedSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_key: Cow<'a, GenericPublicKey<Pub>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys: vec![signing_key],
            message,
            _phantom: PhantomData,
        }
    }

    /// Instantiate self where `signature` is signed by multiple public keys.
    pub fn multiple_pubkeys(
        signature: impl Into<WrappedSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_keys: Vec<Cow<'a, GenericPublicKey<Pub>>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys,
            message,
            _phantom: PhantomData,
        }
    }

    /// Returns `true` if `self.signature` is a signature across `self.message` by
    /// `self.signing_keys`.
    pub fn verify(self) -> bool {
        let pubkeys = self
            .signing_keys
            .iter()
            .map(|pk| pk.as_ref())
            .collect::<Vec<_>>();

        self.signature
            .fast_aggregate_verify(self.message, &pubkeys[..])
    }
}
