use super::*;
use crate::case_result::compare_result;
use bls::{compress_g2, hash_on_g2};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsG2CompressedInput {
    pub message: String,
    pub domain: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlsG2Compressed {
    pub input: BlsG2CompressedInput,
    pub output: Vec<String>,
}

impl YamlDecode for BlsG2Compressed {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl Case for BlsG2Compressed {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        // FIXME: re-enable in v0.7
        // https://github.com/ethereum/eth2.0-spec-tests/issues/3
        if _case_index == 4 {
            return Err(Error::SkippedKnownFailure);
        }

        // Convert message and domain to required types
        let msg = hex::decode(&self.input.message[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let d = hex::decode(&self.input.domain[2..])
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let d = bytes_to_u64(&d);

        // Calculate the point and convert it to compressed bytes
        let mut point = hash_on_g2(&msg, d);
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

// Converts a vector to u64 (from big endian)
fn bytes_to_u64(array: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for (i, value) in array.iter().rev().enumerate() {
        if i == 8 {
            break;
        }
        result += u64::pow(2, i as u32 * 8) * u64::from(*value);
    }
    result
}
