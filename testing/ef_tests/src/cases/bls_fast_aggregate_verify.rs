use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKey, PublicKeyBytes};
use serde_derive::Deserialize;
use std::convert::TryInto;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsFastAggregateVerifyInput {
    pub pubkeys: Vec<PublicKeyBytes>,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsFastAggregateVerify {
    pub input: BlsFastAggregateVerifyInput,
    pub output: bool,
}

impl BlsCase for BlsFastAggregateVerify {}

impl Case for BlsFastAggregateVerify {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let message = Hash256::from_slice(
            &hex::decode(&self.input.message[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?,
        );

        let pubkeys = self
            .input
            .pubkeys
            .iter()
            .map(|pkb| pkb.try_into())
            .collect::<Result<Vec<PublicKey>, bls::Error>>()
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let pubkey_refs = pubkeys.iter().collect::<Vec<_>>();

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| AggregateSignature::deserialize(&bytes).ok())
            .map(|signature| signature.fast_aggregate_verify(message, &pubkey_refs))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
