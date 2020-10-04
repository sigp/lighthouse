use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{PublicKey, Signature, SignatureBytes};
use serde_derive::Deserialize;
use std::convert::TryInto;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsVerifyInput {
    pub pubkey: PublicKey,
    pub message: String,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsVerify {
    pub input: BlsVerifyInput,
    pub output: bool,
}

impl BlsCase for BlsVerify {}

impl Case for BlsVerify {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let message = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_ok = (&self.input.signature)
            .try_into()
            .map(|signature: Signature| {
                signature.verify(&self.input.pubkey, Hash256::from_slice(&message))
            })
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
