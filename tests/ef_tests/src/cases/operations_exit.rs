use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_exits;
use types::{BeaconState, EthSpec, VoluntaryExit};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsExit<E: EthSpec> {
    pub description: String,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub voluntary_exit: VoluntaryExit,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsExit<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsExit<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let exit = self.voluntary_exit.clone();
        let mut expected = self.post.clone();

        // Exit processing requires the epoch cache.
        state.build_all_caches(&E::default_spec()).unwrap();

        let result = process_exits(&mut state, &[exit], &E::default_spec());

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
