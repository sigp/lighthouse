use super::*;
use crate::case_result::compare_result;
use crate::cases::common::BlsCase;
use bls::{AggregatePublicKey, PublicKey};
use serde_derive::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BlsAggregatePubkeys {
    pub input: Vec<String>,
    pub output: String,
}

impl BlsCase for BlsAggregatePubkeys {}

impl Case for BlsAggregatePubkeys {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut aggregate_pubkey = AggregatePublicKey::new();

        for key_str in &self.input {
            let key = hex::decode(&key_str[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
            let key = PublicKey::from_bytes(&key)
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

            aggregate_pubkey.add(&key);
        }

        let output_bytes = Some(
            hex::decode(&self.output[2..])
                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?,
        );
        let aggregate_pubkey = Ok(aggregate_pubkey.as_raw().as_bytes());

        compare_result::<Vec<u8>, Vec<u8>>(&aggregate_pubkey, &output_bytes)
    }
}
