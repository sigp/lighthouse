use crate::{PublicKey, Signature};
use std::borrow::Cow;

type Message = [u8; 32];

#[derive(Clone, Debug)]
pub struct SignedMessage<'a> {
    signing_keys: Vec<Cow<'a, PublicKey>>,
    message: Message,
}

impl<'a> SignedMessage<'a> {
    pub fn new(signing_keys: Vec<Cow<'a, PublicKey>>, message: Message) -> Self {
        Self {
            signing_keys,
            message,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignatureSet<'a> {
    pub signature: &'a Signature,
    signed_messages: Vec<SignedMessage<'a>>,
}

impl<'a> SignatureSet<'a> {
    pub fn single<S>(
        signature: &'a Signature,
        signing_key: Cow<'a, PublicKey>,
        message: Message,
    ) -> Self {
        Self {
            signature,
            signed_messages: vec![SignedMessage::new(vec![signing_key], message)],
        }
    }

    pub fn new<S>(signature: &'a Signature, signed_messages: Vec<SignedMessage<'a>>) -> Self {
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
                signed_message.signing_keys[0].clone().into_owned()
            } else {
                let mut aggregate = PublicKey::zero();
                aggregate.add_assign_multiple(
                    signed_message.signing_keys.iter().map(|cow| cow.as_ref()),
                );
                aggregate
            };

            pubkeys.push(pubkey.point);
        });

        self.signature.fast_aggregate_verify(&pubkeys, &messages)
    }
}

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
    let aggregate = public_keys
        .iter()
        .fold(PublicKey::zero(), |mut aggregate, pubkey| {
            aggregate.add_assign(&pubkey);
            aggregate
        });

    // Milagro requires that the `affine` function is called after aggregating keys.
    #[cfg(feature = "milagro")]
    #[cfg(not(feature = "herumi"))]
    #[cfg(not(feature = "fake_crypto"))]
    aggregate.point_mut().affine();

    aggregate
}
