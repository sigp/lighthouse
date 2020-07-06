use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKeyBytes};
use serde_derive::Deserialize;
use std::borrow::Cow;
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

        let signed_messages = self
            .input
            .pubkeys
            .iter()
            .map(|pkb| pkb.try_into().map(|pk| (Cow::Owned(pk), message)))
            .collect::<Result<Vec<_>, bls::Error>>()
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| AggregateSignature::deserialize(&bytes).ok())
            .map(|signature| signature.fast_aggregate_verify(signed_messages.into_iter()))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
