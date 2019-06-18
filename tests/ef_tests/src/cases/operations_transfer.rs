use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_transfers;
use types::{BeaconState, EthSpec, Transfer};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsTransfer<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub transfer: Transfer,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsTransfer<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsTransfer<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let transfer = self.transfer.clone();
        let mut expected = self.post.clone();

        // Transfer processing requires the epoch cache.
        state.build_all_caches(&E::default_spec()).unwrap();

        let mut spec = E::default_spec();
        spec.max_transfers = 1;

        let result = process_transfers(&mut state, &[transfer], &spec);

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
