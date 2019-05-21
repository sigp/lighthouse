use super::*;
use crate::case_result::compare_result;
use bls::{AggregateSignature, Signature};
use serde_derive::Deserialize;
use types::EthSpec;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateSigs {
    pub input: Vec<String>,
    pub output: String,
}

impl YamlDecode for BlsAggregateSigs {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl EfTest for Cases<BlsAggregateSigs> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = bls_add_signatures(&tc.input, &tc.output);

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `aggregate_sigs` test case.
fn bls_add_signatures(inputs: &[String], output: &String) -> Result<(), Error> {
    let mut aggregate_signature = AggregateSignature::new();

    for key_str in inputs {
        let sig =
            hex::decode(&key_str[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let sig = Signature::from_bytes(&sig)
            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        aggregate_signature.add(&sig);
    }

    let output_bytes =
        Some(hex::decode(&output[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?);
    let aggregate_signature = Ok(aggregate_signature.as_bytes());

    compare_result::<Vec<u8>, Vec<u8>>(&aggregate_signature, &output_bytes)
}
