use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregateSignature, Signature};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateSigs {
    pub input: Vec<String>,
    pub output: String,
}

impl BlsCase for BlsAggregateSigs {}

impl Case for BlsAggregateSigs {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut aggregate_signature = AggregateSignature::new();

        for key_str in &self.input {
            let sig = hex::decode(&key_str[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
            let sig = Signature::from_bytes(&sig)
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

            aggregate_signature.add(&sig);
        }

        // Check for YAML null value, indicating invalid input. This is a bit of a hack,
        // as our mutating `aggregate_signature.add` API doesn't play nicely with aggregating 0
        // inputs.
        let output_bytes = if self.output == "~" {
            AggregateSignature::new().as_bytes().to_vec()
        } else {
            hex::decode(&self.output[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?
        };
        let aggregate_signature = Ok(aggregate_signature.as_bytes().to_vec());

        compare_result::<Vec<u8>, Vec<u8>>(&aggregate_signature, &Some(output_bytes))
    }
}
