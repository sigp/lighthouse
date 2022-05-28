use super::*;
use crate::case_result::compare_result;
use crate::decode::yaml_decode_file;
use bls::{AggregateSignature, PublicKeyBytes};
use serde_derive::Deserialize;
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
    pub output: String,
}

impl LoadCase for BlsBatchVerify {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        yaml_decode_file(&path)
    }
}

impl Case for BlsBatchVerify {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let messages = self
            .input
            .messages
            .iter()
            .map(|message| {
                let bytes = hex::decode(&message[2..])
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
                Ok(Hash256::from_slice(&bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let pubkeys_result = self
            .input
            .pubkeys
            .iter()
            .map(|pkb| {
                pkb.decompress()
                    .map_err(|_| Error::FailedToParseTest("pubkeys parse error".to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let signature_result = self
            .input
            .signatures
            .iter()
            .map(|s| {
                hex::decode(&s[2..])
                    .ok()
                    .and_then(|bytes: Vec<u8>| AggregateSignature::deserialize(&bytes).ok())
                    .ok_or(Error::FailedToParseTest(format!(
                        "{:?}",
                        self.input.signatures
                    )))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}
