use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKeyBytes};
use serde_derive::Deserialize;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateVerifyInput {
    pub pubkeys: Vec<PublicKeyBytes>,
    pub messages: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateVerify {
    pub input: BlsAggregateVerifyInput,
    pub output: bool,
}

impl BlsCase for BlsAggregateVerify {}

impl Case for BlsAggregateVerify {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Base
    }

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
            .map(|pkb| pkb.decompress())
            .collect::<Result<Vec<_>, _>>();

        let pubkeys = match pubkeys_result {
            Ok(pubkeys) => pubkeys,
            Err(bls::Error::InvalidInfinityPublicKey) if !self.output => {
                return Ok(());
            }
            Err(e) => return Err(Error::FailedToParseTest(format!("{:?}", e))),
        };

        let pubkey_refs = pubkeys.iter().collect::<Vec<_>>();

        let signature_bytes = hex::decode(&self.input.signature[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature_valid = AggregateSignature::deserialize(&signature_bytes)
            .ok()
            .map(|signature| signature.aggregate_verify(&messages, &pubkey_refs[..]))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_valid), &Some(self.output))
    }
}
