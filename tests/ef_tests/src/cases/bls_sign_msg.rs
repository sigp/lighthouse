use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{SecretKey, Signature};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSignInput {
    pub privkey: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSign {
    pub input: BlsSignInput,
    pub output: String,
}

impl BlsCase for BlsSign {}

impl Case for BlsSign {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        // Convert private_key and message to required types
        let sk = hex::decode(&self.input.privkey[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let sk = SecretKey::from_bytes(&sk).unwrap();
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature = Signature::new(&msg, &sk);

        // Convert the output to one set of bytes
        let decoded = hex::decode(&self.output[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(signature.as_bytes()), &Some(decoded))
    }
}
