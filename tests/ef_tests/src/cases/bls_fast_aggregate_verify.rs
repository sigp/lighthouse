use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregatePublicKey, AggregateSignature, PublicKey, PublicKeyBytes};
use serde_derive::Deserialize;
use std::convert::TryInto;

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
        let message = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_ok = self
            .input
            .pubkeys
            .iter()
            .try_fold(
                AggregatePublicKey::new(),
                |mut agg, pkb| -> Option<AggregatePublicKey> {
                    let pk: Result<PublicKey, ssz::DecodeError> = pkb.try_into();
                    agg.add(&pk.ok()?);
                    Some(agg)
                },
            )
            .and_then(|aggregate_pubkey| {
                hex::decode(&self.input.signature[2..])
                    .ok()
                    .and_then(|bytes: Vec<u8>| AggregateSignature::from_bytes(&bytes).ok())
                    .map(|signature| signature.verify(&message, &aggregate_pubkey))
            })
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
