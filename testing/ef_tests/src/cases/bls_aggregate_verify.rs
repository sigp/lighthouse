use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKey};
use serde_derive::Deserialize;
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
                let bytes = hex::decode(&message[2..])
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
                Ok(Hash256::from_slice(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let pubkey_refs = self.input.pubkeys.iter().collect::<Vec<_>>();

        let signature_bytes = hex::decode(&self.input.signature[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_valid = AggregateSignature::deserialize(&signature_bytes)
            .ok()
            .map(|signature| signature.aggregate_verify(&messages, &pubkey_refs))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_valid), &Some(self.output))
    }
}
