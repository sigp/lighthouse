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
    pub output: String,
}

impl BlsCase for BlsSign {}

impl Case for BlsSign {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        // Convert private_key and message to required types
        let sk = hex::decode(&self.input.privkey[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        assert_eq!(sk.len(), 32);

        let sk = SecretKey::deserialize(&sk).unwrap();
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        let signature = sk.sign(Hash256::from_slice(&msg));

        // Convert the output to one set of bytes
        let decoded = hex::decode(&self.output[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(signature.serialize().to_vec()), &Some(decoded))
    }
}
