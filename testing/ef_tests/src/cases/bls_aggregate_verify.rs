use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKey, SignatureSet, SignedMessage};
use serde_derive::Deserialize;
use std::borrow::Cow;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateVerifyInput {
    pub pubkeys: Vec<PublicKey>,
    pub messages: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateVerify {
    pub input: BlsAggregateVerifyInput,
    pub output: bool,
}

impl BlsCase for BlsAggregateVerify {}

impl Case for BlsAggregateVerify {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let messages = self
            .input
            .messages
            .iter()
            .map(|message| {
                hex::decode(&message[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
            })
            .collect::<Result<Vec<Vec<_>>, _>>()?;

        let message_refs = messages
            .iter()
            .map(|x| x.as_slice())
            .collect::<Vec<&[u8]>>();

        let pubkey_refs = self.input.pubkeys.iter().collect::<Vec<_>>();

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| AggregateSignature::deserialize(&bytes).ok())
            .map(|signature| {
                let signed_messages = message_refs
                    .into_iter()
                    .zip(pubkey_refs.into_iter())
                    .map(|(message, pubkey)| {
                        SignedMessage::new(
                            vec![Cow::Borrowed(pubkey)],
                            Hash256::from_slice(message),
                        )
                    })
                    .collect();

                SignatureSet::from_components(&signature, signed_messages).is_valid()
            })
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
