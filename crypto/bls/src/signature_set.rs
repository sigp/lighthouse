use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::{AggregateSignature, TAggregateSignature},
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Hash256,
};
use std::borrow::Cow;
use std::marker::PhantomData;

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

#[derive(Clone)]
pub struct SignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: Clone,
    Sig: Clone,
    AggSig: Clone,
{
    pub signature: Cow<'a, AggregateSignature<Pub, AggPub, Sig, AggSig>>,
    pub(crate) signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
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
    pub fn single(
        signature: impl Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_key: Cow<'a, PublicKey<Pub>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys: vec![signing_key],
            message,
            _phantom: PhantomData,
        }
    }

    pub fn new(
        signature: impl Into<GenericSignature<'a, Pub, AggPub, Sig, AggSig>>,
        signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature: signature.into().aggregate,
            signing_keys,
            message,
            _phantom: PhantomData,
        }
    }

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
