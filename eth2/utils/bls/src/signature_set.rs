use crate::{AggregateSignature, PublicKey, Signature};
use std::borrow::Cow;

#[cfg(not(feature = "fake_crypto"))]
use milagro_bls::{
    AggregatePublicKey as RawAggregatePublicKey, AggregateSignature as RawAggregateSignature,
    PublicKey as RawPublicKey,
};

#[cfg(feature = "fake_crypto")]
use crate::fakes::{
    AggregatePublicKey as RawAggregatePublicKey, AggregateSignature as RawAggregateSignature,
    PublicKey as RawPublicKey,
};

type Message = Vec<u8>;

#[derive(Clone, Debug)]
pub struct SignatureSet {
    pub signature: RawAggregateSignature,
    signing_keys: RawAggregatePublicKey,
    message: Message,
}

impl SignatureSet {
    pub fn single(signature: &Signature, signing_key: Cow<PublicKey>, message: Message) -> Self {
        Self {
            signature: RawAggregateSignature::from_signature(signature.as_raw()),
            signing_keys: RawAggregatePublicKey::from_public_key(signing_key.as_raw()),
            message,
        }
    }

    pub fn new(
        signature: &AggregateSignature,
        signing_keys: Vec<Cow<PublicKey>>,
        message: Message,
    ) -> Self
where {
        let signing_keys_refs: Vec<&RawPublicKey> =
            signing_keys.iter().map(|pk| pk.as_raw()).collect();
        Self {
            signature: signature.as_raw().clone(),
            signing_keys: RawAggregatePublicKey::aggregate(&signing_keys_refs),
            message,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.signature
            .fast_aggregate_verify_pre_aggregated(&self.message, &self.signing_keys)
    }
}

#[cfg(not(feature = "fake_crypto"))]
type VerifySet<'a> = (
    &'a RawAggregateSignature,
    &'a RawAggregatePublicKey,
    &'a [u8],
);

#[cfg(not(feature = "fake_crypto"))]
pub fn verify_signature_sets<'a>(sets: Vec<SignatureSet>) -> bool {
    let rng = &mut rand::thread_rng();
    let verify_set: Vec<VerifySet> = sets
        .iter()
        .map(|ss| (&ss.signature, &ss.signing_keys, ss.message.as_slice()))
        .collect();
    RawAggregateSignature::verify_multiple_aggregate_signatures(rng, verify_set.into_iter())
}

#[cfg(feature = "fake_crypto")]
pub fn verify_signature_sets<'a>(_: Vec<SignatureSet>) -> bool {
    true
}
