use super::*;
use crate::bls_setting::BlsSetting;
use serde_derive::Deserialize;
use state_processing::is_valid_genesis_state;
use types::{BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct GenesisValidity<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    pub genesis: BeaconState<E>,
    pub is_valid: bool,
}

impl<E: EthSpec> YamlDecode for GenesisValidity<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(yaml).unwrap())
    }
}

impl<E: EthSpec> Case for GenesisValidity<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        self.bls_setting.unwrap_or_default().check()?;
        let spec = &E::default_spec();

        let is_valid = is_valid_genesis_state(&self.genesis, spec);

        if is_valid == self.is_valid {
            Ok(())
        } else {
            Err(Error::NotEqual(format!(
                "Got {}, expected {}",
                is_valid, self.is_valid
            )))
        }
    }
}
