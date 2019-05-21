use super::*;
use crate::case_result::compare_result;
use bls::{compress_g2, hash_on_g2};
use ethereum_types::{U128, U256};
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;
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
fn compressed_hash<T>(
    message: &String,
    domain: &String,
    output: &Vec<String>,
) -> Result<(), Error> {
    let msg = hex::decode(&message[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = hex::decode(&domain[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = bytes_to_u64(&d);

    let point = hash_on_g2


    let mut output = hex::decode(&output[0][2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let output_y = hex::decode(&output[1][2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    output.append(&output_y);

    let point = hash_on_g2(&msg, d);
    let point = compress_g2(&point);

    compare_result::<Vec<u8>, Vec<u8>>(Ok(point), Some(output))
}

// Converts a vector to u64 (from little endian)
fn bytes_to_u64(array: &Vec<u8>) -> u64 {
    let mut result: u64 = 0;
    for (i, value) in array.iter().enumerate() {
        if i == 8 {
            break;
        }
        result += u64::pow(2, i * 8) * *value;
    }
    result
}
