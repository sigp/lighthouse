use super::*;
use crate::case_result::compare_result;
use bls::{PublicKey, SecretKey};
use serde_derive::Deserialize;
use types::EthSpec;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsPrivToPub {
    pub input: String,
    pub output: String,
}

impl YamlDecode for BlsPrivToPub {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl EfTest for Cases<BlsPrivToPub> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = secret_to_public(&tc.input, &tc.output);

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `Private key to public key` test case.
fn secret_to_public(secret: &String, output: &String) -> Result<(), Error> {
    // Convert message and domain to required types
    let mut sk =
        hex::decode(&secret[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    pad_to_48(&mut sk);
    let sk = SecretKey::from_bytes(&sk).unwrap();
    let pk = PublicKey::from_secret_key(&sk);

    let decoded =
        hex::decode(&output[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    compare_result::<Vec<u8>, Vec<u8>>(&Ok(pk.as_raw().as_bytes()), &Some(decoded))
}

// Increase the size of an array to 48 bytes
fn pad_to_48(array: &mut Vec<u8>) {
    while array.len() < 48 {
        array.insert(0, 0);
    }
}
