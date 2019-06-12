use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_proposer_slashings;
use types::{BeaconState, EthSpec, ProposerSlashing};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsProposerSlashing<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub proposer_slashing: ProposerSlashing,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsProposerSlashing<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsProposerSlashing<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let proposer_slashing = self.proposer_slashing.clone();
        let mut expected = self.post.clone();

        // Processing requires the epoch cache.
        state.build_all_caches(&E::spec()).unwrap();

        let result = process_proposer_slashings(&mut state, &[proposer_slashing], &E::spec());

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
