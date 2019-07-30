use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_deposits;
use types::{BeaconState, Deposit, EthSpec};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct OperationsDeposit<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    pub pre: BeaconState<E>,
    pub deposit: Deposit,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsDeposit<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsDeposit<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let deposit = self.deposit.clone();
        let mut expected = self.post.clone();

        let result = process_deposits(&mut state, &[deposit], &E::default_spec());

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
