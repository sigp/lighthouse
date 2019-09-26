use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{SecretKey, Signature};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSignInput {
    pub privkey: String,
    pub message: String,
    pub domain: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsSign {
    pub input: BlsSignInput,
    pub output: String,
}

impl BlsCase for BlsSign {}

impl Case for BlsSign {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        // Convert private_key, message and domain to required types
        let mut sk = hex::decode(&self.input.privkey[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        pad_to_48(&mut sk);
        let sk = SecretKey::from_bytes(&sk).unwrap();
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let d = hex::decode(&self.input.domain[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let d = bytes_to_u64(&d);

        let signature = Signature::new(&msg, d, &sk);

        // Convert the output to one set of bytes
        let decoded = hex::decode(&self.output[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(signature.as_bytes()), &Some(decoded))
    }
}

// Converts a vector to u64 (from little endian)
fn bytes_to_u64(array: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(array);
    u64::from_le_bytes(bytes)
}

// Increase the size of an array to 48 bytes
fn pad_to_48(array: &mut Vec<u8>) {
    while array.len() < 48 {
        array.insert(0, 0);
    }
}
