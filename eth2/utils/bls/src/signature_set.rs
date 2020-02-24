use crate::{
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
};
use std::borrow::Cow;

type Message = [u8; 32];

#[derive(Clone, Debug)]
pub struct SignedMessage<'a, Pub>
where
    Pub: TPublicKey + Clone,
{
    pub(crate) signing_keys: Vec<Cow<'a, PublicKey<Pub>>>,
    pub(crate) message: Message,
}

impl<'a, Pub> SignedMessage<'a, Pub>
where
    Pub: TPublicKey + Clone,
{
    pub fn new(signing_keys: Vec<Cow<'a, PublicKey<Pub>>>, message: Message) -> Self {
        Self {
            signing_keys,
            message,
        }
    }
}

#[derive(Clone)]
pub struct SignatureSet<'a, Pub, Sig>
where
    Pub: TPublicKey + Clone,
{
    pub signature: &'a Signature<Pub, Sig>,
    pub(crate) signed_messages: Vec<SignedMessage<'a, Pub>>,
}

impl<'a, Pub, Sig> SignatureSet<'a, Pub, Sig>
where
    Pub: TPublicKey + Clone,
    Sig: TSignature<Pub>,
{
    pub fn single<S>(
        signature: &'a Signature<Pub, Sig>,
        signing_key: Cow<'a, PublicKey<Pub>>,
        message: Message,
    ) -> Self {
        Self {
            signature,
            signed_messages: vec![SignedMessage::new(vec![signing_key], message)],
        }
    }

    pub fn new<S>(
        signature: &'a Signature<Pub, Sig>,
        signed_messages: Vec<SignedMessage<'a, Pub>>,
    ) -> Self {
        Self {
            signature,
            signed_messages,
        }
    }

    pub fn is_valid(&self) -> bool {
        let mut messages: Vec<Message> = vec![];
        let mut pubkeys = vec![];

        self.signed_messages.iter().for_each(|signed_message| {
            messages.push(signed_message.message.clone());

            let pubkey = if signed_message.signing_keys.len() == 1 {
                signed_message.signing_keys[0]
                    .clone()
                    .into_owned()
                    .into_point()
            } else {
                let mut aggregate = PublicKey::zero();
                aggregate.add_assign_multiple(
                    signed_message.signing_keys.iter().map(|cow| cow.as_ref()),
                );
                aggregate.into_point()
            };

            pubkeys.push(pubkey);
        });

        self.signature
            .fast_aggregate_verify(&pubkeys[..], &messages)
    }
}

/*
type VerifySet<'a> = (Signature, Vec<PublicKey>, Vec<Message>);

impl<'a> Into<VerifySet<'a>> for SignatureSet<'a> {
    fn into(self) -> VerifySet<'a> {
        let signature = self.signature.clone();

        let (pubkeys, messages): (Vec<PublicKey>, Vec<Message>) = self
            .signed_messages
            .into_iter()
            .map(|signed_message| {
                let key = if signed_message.signing_keys.len() == 1 {
                    signed_message.signing_keys[0].clone().into_owned()
                } else {
                    aggregate_public_keys(&signed_message.signing_keys)
                };

                (key, signed_message.message)
            })
            .unzip();

        (signature, pubkeys, messages)
    }
}

/// Create an aggregate public key for a list of validators, failing if any key can't be found.
fn aggregate_public_keys<'a>(public_keys: &'a [Cow<'a, PublicKey>]) -> PublicKey {
    let mut aggregate = PublicKey::zero();

    aggregate.add_assign_multiple(public_keys.iter().map(|cow| cow.as_ref()));

    aggregate
}
*/
