use super::*;
use crate::case_result::compare_result;
use crate::impl_bls_load_case;
use bls::{verify_signature_sets, BlsWrappedSignature, PublicKeyBytes, Signature, SignatureSet};
use serde_derive::Deserialize;
use std::borrow::Cow;
use types::Hash256;
#[derive(Debug, Clone, Deserialize)]
pub struct BlsBatchVerifyInput {
    pubkeys: Vec<PublicKeyBytes>,
    messages: Vec<String>,
    signatures: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsBatchVerify {
    pub input: BlsBatchVerifyInput,
    pub output: bool,
}

impl_bls_load_case!(BlsBatchVerify);

impl Case for BlsBatchVerify {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let messages = self
            .input
            .messages
            .iter()
            .map(|message| {
                hex::decode(&message[2..])
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
                    .map(|bytes| Hash256::from_slice(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let pubkeys = self
            .input
            .pubkeys
            .iter()
            .map(|pkb| {
                pkb.decompress()
                    .map_err(|_| Error::FailedToParseTest("pubkeys parse error".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signatures = self
            .input
            .signatures
            .iter()
            .map(|s| {
                hex::decode(&s[2..])
                    .ok()
                    .and_then(|bytes: Vec<u8>| Signature::deserialize(&bytes).ok())
                    .ok_or_else(|| Error::FailedToParseTest(format!("{:?}", self.input.signatures)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signature_set = messages
            .iter()
            .zip(pubkeys.iter())
            .zip(signatures.iter())
            .map(|((&message, pubkey), signature)| {
                let wraped_signature = BlsWrappedSignature::from(signature);
                SignatureSet::single_pubkey(wraped_signature, Cow::Borrowed(pubkey), message)
            })
            .collect::<Vec<_>>();

        let signature_valid = verify_signature_sets(signature_set.iter());

        compare_result::<bool, ()>(&Ok(signature_valid), &Some(self.output))
    }
}
