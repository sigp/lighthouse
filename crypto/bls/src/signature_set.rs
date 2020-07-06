use crate::{
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Hash256,
};
use std::borrow::Cow;

#[derive(Clone)]
pub struct SignatureSet<'a, Pub, Sig>
where
    Pub: TPublicKey + Clone,
{
    pub signature: &'a Signature<Pub, Sig>,
    pub(crate) signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
    pub(crate) message: Hash256,
}

impl<'a, Pub, Sig> SignatureSet<'a, Pub, Sig>
where
    Pub: TPublicKey + Clone,
    Sig: TSignature<Pub>,
{
    pub fn single(
        signature: &'a Signature<Pub, Sig>,
        signing_key: Cow<'a, PublicKey<Pub>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature,
            signing_keys: vec![signing_key],
            message,
        }
    }

    pub fn new(
        signature: &'a Signature<Pub, Sig>,
        signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
        message: Hash256,
    ) -> Self {
        Self {
            signature,
            signing_keys,
            message,
        }
    }

    pub fn is_valid(self) -> bool {
        let pubkeys = self
            .signing_keys
            .iter()
            .map(|pk| pk.as_ref())
            .collect::<Vec<_>>();
        self.signature.fast_aggregate_verify(self.message, &pubkeys)
    }
}
