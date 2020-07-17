use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::{AggregateSignature, TAggregateSignature},
    public_key::{GenericPublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Hash256,
};
use std::borrow::Cow;
use std::marker::PhantomData;

/// A generic way to represent a `Signature` or `AggregateSignature`.
pub struct GenericSignature<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    aggregate: Cow<'a, AggregateSignature<Pub, AggPub, Sig, AggSig>>,
}

impl<'a, Pub, AggPub, Sig, AggSig> Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>
    for &'a Signature<Pub, Sig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    fn into(self) -> GenericSignature<'a, Pub, AggPub, Sig, AggSig> {
        let mut aggregate: AggregateSignature<Pub, AggPub, Sig, AggSig> =
            AggregateSignature::zero();
        aggregate.add_assign(self);
        GenericSignature {
            aggregate: Cow::Owned(aggregate),
        }
    }
}

impl<'a, Pub, AggPub, Sig, AggSig> Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>
    for &'a AggregateSignature<Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    fn into(self) -> GenericSignature<'a, Pub, AggPub, Sig, AggSig> {
        GenericSignature {
            aggregate: Cow::Borrowed(self),
        }
    }
}

/// A generic way to represent a signature across a message by multiple public keys.
///
/// This struct is primarily useful in a collection (e.g., `Vec<SignatureSet>`) so we can perform
/// multiple-signature verification which is much faster than verifying each signature
/// individually.
#[derive(Clone)]
pub struct SignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    pub signature: Cow<'a, AggregateSignature<Pub, AggPub, Sig, AggSig>>,
    pub(crate) signing_keys: Vec<Cow<'a, GenericPublicKey<Pub>>>,
    pub(crate) message: Hash256,
    _phantom: PhantomData<Sig>,
}

impl<'a, Pub, AggPub, Sig, AggSig> SignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey + Clone,
    Sig: TSignature<Pub> + Clone,
    AggSig: TAggregateSignature<Pub, AggPub, Sig> + Clone,
{
    /// Instantiate self where `signature` is only signed by a single public key.
    pub fn single_pubkey(
        signature: impl Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>,
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
        signature: impl Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>,
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
    pub fn is_valid(self) -> bool {
        let pubkeys = self
            .signing_keys
            .iter()
            .map(|pk| pk.as_ref())
            .collect::<Vec<_>>();

        self.signature
            .fast_aggregate_verify(self.message, &pubkeys[..])
    }
}
