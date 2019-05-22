use super::*;
use crate::case_result::compare_result;
use bls::{SecretKey, Signature};
use serde_derive::Deserialize;
use types::EthSpec;

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

impl YamlDecode for BlsSign {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl EfTest for Cases<BlsSign> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = sign_msg(
                    &tc.input.privkey,
                    &tc.input.message,
                    &tc.input.domain,
                    &tc.output,
                );

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `compressed hash to g2` test case.
fn sign_msg(
    private_key: &String,
    message: &String,
    domain: &String,
    output: &String,
) -> Result<(), Error> {
    // Convert private_key, message and domain to required types
    let mut sk =
        hex::decode(&private_key[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    pad_to_48(&mut sk);
    let sk = SecretKey::from_bytes(&sk).unwrap();
    let msg =
        hex::decode(&message[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = hex::decode(&domain[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let d = bytes_to_u64(&d);

    let signature = Signature::new(&msg, d, &sk);

    // Convert the output to one set of bytes
    let decoded =
        hex::decode(&output[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    compare_result::<Vec<u8>, Vec<u8>>(&Ok(signature.as_bytes()), &Some(decoded))
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

// Increase the size of an array to 48 bytes
fn pad_to_48(array: &mut Vec<u8>) {
    while array.len() < 48 {
        array.insert(0, 0);
    }
}
