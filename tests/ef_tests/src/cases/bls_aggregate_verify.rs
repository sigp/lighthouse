use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{Hash256, PublicKey, Signature};
use serde_derive::Deserialize;
use ssz::Decode;
use std::borrow::Cow;

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
        let pubkey_msgs = self
            .input
            .pairs
            .iter()
            .map(|pair| {
                let bytes = hex::decode(&pair.message[2..])
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

                Ok((Cow::Borrowed(&pair.pubkey), Hash256::from_slice(&bytes)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| Signature::from_ssz_bytes(&bytes).ok())
            .map(|signature| signature.fast_aggregate_verify(pubkey_msgs.into_iter()))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
