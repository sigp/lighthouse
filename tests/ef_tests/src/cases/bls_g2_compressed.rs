use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{compress_g2, hash_on_g2};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsG2CompressedInput {
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsG2Compressed {
    pub input: BlsG2CompressedInput,
    pub output: Vec<String>,
}

impl BlsCase for BlsG2Compressed {}

impl Case for BlsG2Compressed {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        // Calculate the point and convert it to compressed bytes
        let mut point = hash_on_g2(&msg);
        let point = compress_g2(&mut point);

        // Convert the output to one set of bytes
        let mut decoded = hex::decode(&self.output[0][2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let mut decoded_y = hex::decode(&self.output[1][2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        decoded.append(&mut decoded_y);

        compare_result::<Vec<u8>, Vec<u8>>(&Ok(point), &Some(decoded))
    }
}
