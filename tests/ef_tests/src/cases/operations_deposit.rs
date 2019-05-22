use super::*;
use crate::case_result::compare_result;
use serde_derive::Deserialize;
use state_processing::per_block_processing::process_deposits;
use types::{BeaconState, Deposit, EthSpec};

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsDeposit<E: EthSpec> {
    pub description: String,
    #[serde(bound = "E: EthSpec")]
    pub pre: BeaconState<E>,
    pub deposit: Deposit,
    #[serde(bound = "E: EthSpec")]
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsDeposit<E> {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsDeposit<E> {
    fn result(&self) -> Result<(), Error> {
        let mut state = self.pre.clone();
        let deposit = self.deposit.clone();

        let result = process_deposits(&mut state, &[deposit], &E::spec()).and_then(|_| Ok(state));

        compare_result(&result, &self.post)
    }
}
