use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::{AggregateSignature, TAggregateSignature},
    public_key::{PublicKey, TPublicKey},
    signature::TSignature,
    Hash256,
};
use std::borrow::Cow;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct SignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
{
    pub signature: &'a AggregateSignature<Pub, AggPub, Sig, AggSig>,
    pub(crate) signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
    pub(crate) message: Hash256,
    _phantom: PhantomData<Sig>,
}

impl<'a, Pub, AggPub, Sig, AggSig> SignatureSet<'a, Pub, AggPub, Sig, AggSig>
where
    Pub: TPublicKey + Clone,
    AggPub: TAggregatePublicKey + Clone,
    Sig: TSignature<Pub>,
    AggSig: TAggregateSignature<Pub, AggPub, Sig>,
{
    pub fn single(
        signature: &'a AggregateSignature<Pub, AggPub, Sig, AggSig>,
        signing_key: Cow<'a, PublicKey<Pub>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature,
            signing_keys: vec![signing_key],
            message,
            _phantom: PhantomData,
        }
    }

    pub fn new(
        signature: &'a AggregateSignature<Pub, AggPub, Sig, AggSig>,
        signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature,
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
