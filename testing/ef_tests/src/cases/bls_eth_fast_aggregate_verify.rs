use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, PublicKeyBytes};
use serde_derive::Deserialize;
use std::convert::TryInto;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsEthFastAggregateVerifyInput {
    pub pubkeys: Vec<PublicKeyBytes>,
    #[serde(alias = "messages")]
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsEthFastAggregateVerify {
    pub input: BlsEthFastAggregateVerifyInput,
    pub output: bool,
}

impl BlsCase for BlsEthFastAggregateVerify {}

impl Case for BlsEthFastAggregateVerify {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Altair
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let message = Hash256::from_slice(
            &hex::decode(&self.input.message[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?,
        );

        let pubkeys_result = self
            .input
            .pubkeys
            .iter()
            .map(|pkb| pkb.try_into())
            .collect::<Result<Vec<_>, _>>();

        let pubkeys = match pubkeys_result {
            Ok(pubkeys) => pubkeys,
            Err(bls::Error::InvalidInfinityPublicKey) if !self.output => {
                return Ok(());
            }
            Err(e) => return Err(Error::FailedToParseTest(format!("{:?}", e))),
        };

        let pubkey_refs = pubkeys.iter().collect::<Vec<_>>();

        let signature_ok = hex::decode(&self.input.signature[2..])
            .ok()
            .and_then(|bytes: Vec<u8>| AggregateSignature::deserialize(&bytes).ok())
            .map(|signature| signature.eth_fast_aggregate_verify(message, &pubkey_refs))
            .unwrap_or(false);

        compare_result::<bool, ()>(&Ok(signature_ok), &Some(self.output))
    }
}
