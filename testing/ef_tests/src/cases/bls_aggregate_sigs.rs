use super::*;
use crate::case_result::compare_result;
use crate::impl_bls_load_case;
use bls::{AggregateSignature, Signature};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateSigs {
    pub input: Vec<String>,
    pub output: Option<String>,
}

impl_bls_load_case!(BlsAggregateSigs);

impl Case for BlsAggregateSigs {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let mut aggregate_signature = AggregateSignature::infinity();

        for key_str in &self.input {
            let sig = hex::decode(&key_str[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
            let sig = Signature::deserialize(&sig)
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

            aggregate_signature.add_assign(&sig);
        }

        let output_bytes = match self.output.as_deref() {
            // Check for YAML null value, indicating invalid input. This is a bit of a hack,
            // as our mutating `aggregate_signature.add` API doesn't play nicely with aggregating 0
            // inputs.
            Some("~") | None => AggregateSignature::infinity().serialize().to_vec(),
            Some(output) => hex::decode(&output[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?,
        };
        let aggregate_signature = Ok(aggregate_signature.serialize().to_vec());

        compare_result::<Vec<u8>, Vec<u8>>(&aggregate_signature, &Some(output_bytes))
    }
}
