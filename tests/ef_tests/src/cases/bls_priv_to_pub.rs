use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{PublicKey, SecretKey};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsPrivToPub {
    pub input: String,
    pub output: String,
}

impl BlsCase for BlsPrivToPub {}

impl Case for BlsPrivToPub {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let secret = &self.input;

        // Convert message and domain to required types
        let mut sk =
            hex::decode(&secret[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        pad_to_48(&mut sk);
        let sk = SecretKey::from_bytes(&sk).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        let decoded = hex::decode(&self.output[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(pk.as_raw().as_bytes()), &Some(decoded))
    }
}

// Increase the size of an array to 48 bytes
fn pad_to_48(array: &mut Vec<u8>) {
    while array.len() < 48 {
        array.insert(0, 0);
    }
}
