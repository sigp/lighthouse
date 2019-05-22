use super::*;
use crate::case_result::compare_result;
use bls::{compress_g2, hash_on_g2};
use serde_derive::Deserialize;
use types::EthSpec;

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
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl EfTest for Cases<BlsG2Compressed> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = compressed_hash(&tc.input.message, &tc.input.domain, &tc.output);

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `compressed hash to g2` test case.
fn compressed_hash(message: &String, domain: &String, output: &Vec<String>) -> Result<(), Error> {
    // Convert message and domain to required types
    let msg =
        hex::decode(&message[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = hex::decode(&domain[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = bytes_to_u64(&d);

    // Calculate the point and convert it to compressed bytes
    let mut point = hash_on_g2(&msg, d);
    let point = compress_g2(&mut point);

    // Convert the output to one set of bytes
    let mut decoded =
        hex::decode(&output[0][2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let mut decoded_y =
        hex::decode(&output[1][2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    decoded.append(&mut decoded_y);

    compare_result::<Vec<u8>, Vec<u8>>(&Ok(point), &Some(decoded))
}

// Converts a vector to u64 (from big endian)
fn bytes_to_u64(array: &Vec<u8>) -> u64 {
    let mut result: u64 = 0;
    for (i, value) in array.iter().rev().enumerate() {
        if i == 8 {
            break;
        }
        result += u64::pow(2, i as u32 * 8) * (*value as u64);
    }
    result
}
