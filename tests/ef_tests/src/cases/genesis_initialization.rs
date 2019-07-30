use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::initialize_beacon_state_from_eth1;
use types::{BeaconState, Deposit, EthSpec, Hash256};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct GenesisInitialization<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    pub eth1_block_hash: Hash256,
    pub eth1_timestamp: u64,
    pub deposits: Vec<Deposit>,
    pub state: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for GenesisInitialization<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for GenesisInitialization<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;
        let spec = &E::default_spec();

        let mut result = initialize_beacon_state_from_eth1(
            self.eth1_block_hash,
            self.eth1_timestamp,
            self.deposits.clone(),
            spec,
        );

        let mut expected = self.state.clone();

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
