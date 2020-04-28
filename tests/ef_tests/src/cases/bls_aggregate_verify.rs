use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKey};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregatePair {
    pub pubkey: PublicKey,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateVerifyInput {
    pub pairs: Vec<BlsAggregatePair>,
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
            .pairs
            .iter()
            .map(|pair| {
                hex::decode(&pair.message[2..])
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
            })
            .collect::<Result<Vec<Vec<_>>, _>>()?;

        let message_refs = messages
            .iter()
            .map(|x| x.as_slice())
            .collect::<Vec<&[u8]>>();

        let pubkey_refs = self
            .input
            .pairs
            .iter()
            .map(|p| &p.pubkey)
            .collect::<Vec<_>>();

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| AggregateSignature::from_bytes(&bytes).ok())
            .map(|signature| signature.verify_multiple(&message_refs, &pubkey_refs))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
