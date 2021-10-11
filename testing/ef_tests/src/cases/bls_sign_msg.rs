use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::SecretKey;
use serde_derive::Deserialize;
use types::Hash256;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSignInput {
    pub privkey: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSign {
    pub input: BlsSignInput,
    pub output: Option<String>,
}

impl BlsCase for BlsSign {}

impl Case for BlsSign {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Base
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        // Convert private_key and message to required types
        let sk = hex::decode(&self.input.privkey[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        assert_eq!(sk.len(), 32);

        let sk = match SecretKey::deserialize(&sk) {
            Ok(sk) => sk,
            Err(_) if self.output.is_none() => {
                return Ok(());
            }
            Err(e) => return Err(Error::FailedToParseTest(format!("{:?}", e))),
        };
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature = sk.sign(Hash256::from_slice(&msg));

        let decoded = self
            .output
            .as_ref()
            .map(|output| hex::decode(&output[2..]))
            .transpose()
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(signature.serialize().to_vec()), &decoded)
    }
}
