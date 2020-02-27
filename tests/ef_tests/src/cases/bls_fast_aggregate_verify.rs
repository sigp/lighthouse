use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{PublicKey, PublicKeyBytes, Signature};
use serde_derive::Deserialize;
use ssz::Decode;
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
            .try_fold(PublicKey::zero(), |mut agg, pkb| -> Option<PublicKey> {
                let pk: Result<PublicKey, bls::Error> = pkb.decompress();
                agg.add_assign(&pk.ok()?);
                Some(agg)
            })
            .and_then(|aggregate_pubkey| {
                hex::decode(&self.input.signature[2..])
                    .ok()
                    .and_then(|bytes: Vec<u8>| Signature::from_ssz_bytes(&bytes).ok())
                    .map(|signature| signature.verify(&message, &aggregate_pubkey))
            })
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
