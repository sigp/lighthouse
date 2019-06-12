use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_block_header;
use types::{BeaconBlock, BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsBlockHeader<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub block: BeaconBlock,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsBlockHeader<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsBlockHeader<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let mut expected = self.post.clone();

        // Processing requires the epoch cache.
        state.build_all_caches(&E::spec()).unwrap();

        let mut result =
            process_block_header(&mut state, &self.block, &E::spec(), true).map(|_| state);

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
