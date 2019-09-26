use crate::{AggregatePublicKey, AggregateSignature, PublicKey, Signature};
use milagro_bls::{G1Point, G2Point};

#[cfg(not(feature = "fake_crypto"))]
use milagro_bls::AggregateSignature as RawAggregateSignature;

type Message = Vec<u8>;
type Domain = u64;

#[derive(Clone, Debug)]
pub struct SignedMessage<'a> {
    signing_keys: Vec<&'a G1Point>,
    message: Message,
}

impl<'a> SignedMessage<'a> {
    pub fn new<T>(signing_keys: Vec<&'a T>, message: Message) -> Self
    where
        T: G1Ref,
    {
        Self {
            signing_keys: signing_keys.iter().map(|k| k.g1_ref()).collect(),
            message,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSet<'a> {
    pub signature: &'a G2Point,
    signed_messages: Vec<SignedMessage<'a>>,
    domain: Domain,
}

impl<'a> SignatureSet<'a> {
    pub fn single<S, T>(
        signature: &'a S,
        signing_key: &'a T,
        message: Message,
        domain: Domain,
    ) -> Self
    where
        T: G1Ref,
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages: vec![SignedMessage::new(vec![signing_key], message)],
            domain,
        }
    }

    pub fn dual<S, T>(
        signature: &'a S,
        message_0: Message,
        message_0_signing_keys: Vec<&'a T>,
        message_1: Message,
        message_1_signing_keys: Vec<&'a T>,
        domain: Domain,
    ) -> Self
    where
        T: G1Ref,
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages: vec![
                SignedMessage::new(message_0_signing_keys, message_0),
                SignedMessage::new(message_1_signing_keys, message_1),
            ],
            domain,
        }
    }

    pub fn new<S>(signature: &'a S, signed_messages: Vec<SignedMessage<'a>>, domain: Domain) -> Self
    where
        S: G2Ref,
    {
        Self {
            signature: signature.g2_ref(),
            signed_messages,
            domain,
        }
    }

    pub fn is_valid(&self) -> bool {
        let sig = milagro_bls::AggregateSignature {
            point: self.signature.clone(),
        };

        let mut messages: Vec<Vec<u8>> = vec![];
        let mut pubkeys = vec![];

        self.signed_messages.iter().for_each(|signed_message| {
            messages.push(signed_message.message.clone());

            let point = if signed_message.signing_keys.len() == 1 {
                signed_message.signing_keys[0].clone()
            } else {
                aggregate_public_keys(&signed_message.signing_keys)
            };

            pubkeys.push(milagro_bls::AggregatePublicKey { point });
        });

        let pubkey_refs: Vec<&milagro_bls::AggregatePublicKey> =
            pubkeys.iter().map(std::borrow::Borrow::borrow).collect();

        sig.verify_multiple(&messages, self.domain, &pubkey_refs)
    }
}

#[cfg(not(feature = "fake_crypto"))]
pub fn verify_signature_sets<'a>(iter: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    let rng = &mut rand::thread_rng();
    RawAggregateSignature::verify_multiple_signatures(rng, iter.map(Into::into))
}

#[cfg(feature = "fake_crypto")]
pub fn verify_signature_sets<'a>(_iter: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    true
}

type VerifySet<'a> = (G2Point, Vec<G1Point>, Vec<Vec<u8>>, u64);

impl<'a> Into<VerifySet<'a>> for SignatureSet<'a> {
    fn into(self) -> VerifySet<'a> {
        let signature = self.signature.clone();

        let (pubkeys, messages): (Vec<G1Point>, Vec<Message>) = self
            .signed_messages
            .into_iter()
            .map(|signed_message| {
                let key = if signed_message.signing_keys.len() == 1 {
                    signed_message.signing_keys[0].clone()
                } else {
                    aggregate_public_keys(&signed_message.signing_keys)
                };

                (key, signed_message.message)
            })
            .unzip();

        (signature, pubkeys, messages, self.domain)
    }
}

/// Create an aggregate public key for a list of validators, failing if any key can't be found.
fn aggregate_public_keys<'a>(public_keys: &'a [&'a G1Point]) -> G1Point {
    let mut aggregate =
        public_keys
            .iter()
            .fold(AggregatePublicKey::new(), |mut aggregate, &pubkey| {
                aggregate.add_point(pubkey);
                aggregate
            });

    aggregate.affine();

    aggregate.into_raw().point
}

pub trait G1Ref {
    fn g1_ref(&self) -> &G1Point;
}

impl G1Ref for AggregatePublicKey {
    fn g1_ref(&self) -> &G1Point {
        &self.as_raw().point
    }
}

impl G1Ref for PublicKey {
    fn g1_ref(&self) -> &G1Point {
        &self.as_raw().point
    }
}

pub trait G2Ref {
    fn g2_ref(&self) -> &G2Point;
}

impl G2Ref for AggregateSignature {
    fn g2_ref(&self) -> &G2Point {
        &self.as_raw().point
    }
}

impl G2Ref for Signature {
    fn g2_ref(&self) -> &G2Point {
        &self.as_raw().point
    }
}
