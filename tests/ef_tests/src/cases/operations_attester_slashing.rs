use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_attester_slashings;
use types::{AttesterSlashing, BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsAttesterSlashing<E: EthSpec> {
    pub description: String,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub attester_slashing: AttesterSlashing,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsAttesterSlashing<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsAttesterSlashing<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let attester_slashing = self.attester_slashing.clone();
        let mut expected = self.post.clone();

        // Processing requires the epoch cache.
        state.build_all_caches(&E::spec()).unwrap();

        let result = process_attester_slashings(&mut state, &[attester_slashing], &E::spec());

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
