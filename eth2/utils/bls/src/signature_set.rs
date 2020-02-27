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
    pub fn single(
        signature: &'a Signature<Pub, Sig>,
        signing_key: Cow<'a, PublicKey<Pub>>,
        message: Message,
    ) -> Self {
        Self {
            signature,
            signed_messages: vec![SignedMessage::new(vec![signing_key], message)],
        }
    }

    pub fn new(
        signature: &'a Signature<Pub, Sig>,
        signed_messages: Vec<SignedMessage<'a, Pub>>,
    ) -> Self {
        Self {
            signature,
            signed_messages,
        }
    }

    pub fn is_valid(self) -> bool {
        let iter = self.signed_messages.into_iter().map(|mut signed_message| {
            let pubkey = if signed_message.signing_keys.len() == 1 {
                signed_message
                    .signing_keys
                    .pop()
                    .expect("Pop must succeed if len == 1")
            } else {
                let mut aggregate = PublicKey::zero();
                aggregate.add_assign_multiple(
                    signed_message.signing_keys.iter().map(|cow| cow.as_ref()),
                );

                Cow::Owned(aggregate)
            };

            (pubkey, signed_message.message)
        });

        self.signature.fast_aggregate_verify(iter)
    }
}
