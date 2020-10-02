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
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        // FIXME: `verify_infinity_pubkey_and_infinity_signature` fails due to us forbidding the
        // infinity pubkey. This can be removed in the next release (v0.12.4+) of the EF tests.
        if _case_index == 3 {
            return Err(Error::SkippedKnownFailure);
        }

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
