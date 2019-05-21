use super::*;
use crate::case_result::compare_result;
use bls::{AggregatePublicKey, PublicKey};
use ethereum_types::{U128, U256};
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;
use types::EthSpec;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregatePubkeys {
    pub input: Vec<String>,
    pub output: String,
}

impl YamlDecode for BlsAggregatePubkeys {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl EfTest for Cases<BlsAggregatePubkeys> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = bls_add_aggregates::<AggregatePublicKey>(&tc.input, &tc.output);

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `aggregate_pubkeys` test case.
fn bls_add_aggregates<T>(
    inputs: &[String],
    output: &String,
) -> Result<(), Error> {
    let mut aggregate_pubkey = AggregatePublicKey::new();

    for key_str in inputs {
        let key = hex::decode(&key_str[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
        let key = PublicKey::from_bytes(&key).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

        aggregate_pubkey.add(&key);
    }

    let output_bytes = Some(hex::decode(&output[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?);
    let aggregate_pubkey = Ok(aggregate_pubkey.as_raw().as_bytes());

    compare_result::<Vec<u8>, Vec<u8>>(&aggregate_pubkey, &output_bytes)
}
