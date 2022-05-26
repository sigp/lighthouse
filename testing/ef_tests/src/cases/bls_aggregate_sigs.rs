use super::*;
use crate::case_result::compare_result;
use crate::decode::yaml_decode_file;
use bls::{AggregateSignature, Signature};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregateSigs {
    pub input: Vec<String>,
    pub output: String,
}

impl LoadCase for BlsAggregateSigs {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        yaml_decode_file(path)
    }
}

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

        // Check for YAML null value, indicating invalid input. This is a bit of a hack,
        // as our mutating `aggregate_signature.add` API doesn't play nicely with aggregating 0
        // inputs.
        let output_bytes = if self.output == "~" {
            AggregateSignature::infinity().serialize().to_vec()
        } else {
            hex::decode(&self.output[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?
        };
        let aggregate_signature = Ok(aggregate_signature.serialize().to_vec());

        compare_result::<Vec<u8>, Vec<u8>>(&aggregate_signature, &Some(output_bytes))
    }
}
