use super::*;
use serde_derive::Deserialize;
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

/*
impl<T: EthSpec> EfTest for Cases<OperationsDeposit<T>> {
    fn test_results<E: EthSpec>(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                // TODO: run test
                let result = Ok(());

                CaseResult::new(i, tc, result)
            })
            .collect()
    }
}
*/
