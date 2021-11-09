use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{PublicKeyBytes, Signature, SignatureBytes};
use serde_derive::Deserialize;
use std::convert::TryInto;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsVerifyInput {
    pub pubkey: PublicKeyBytes,
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
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Base
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let message = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_ok = (&self.input.signature)
            .try_into()
            .and_then(|signature: Signature| {
                let pk = self.input.pubkey.decompress()?;
                Ok(signature.verify(&pk, Hash256::from_slice(&message)))
            })
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
