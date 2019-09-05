use super::*;
use crate::decode::{ssz_decode_file, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::is_valid_genesis_state;
use std::path::Path;
use types::{BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct GenesisValidity<E: EthSpec> {
    pub genesis: BeaconState<E>,
    pub is_valid: bool,
}

impl<E: EthSpec> LoadCase for GenesisValidity<E> {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        let genesis = ssz_decode_file(&path.join("genesis.ssz"))?;
        let is_valid = yaml_decode_file(&path.join("is_valid.yaml"))?;

        Ok(Self { genesis, is_valid })
    }
}

impl<E: EthSpec> Case for GenesisValidity<E> {
    fn result(&self, _case_index: usize) -> Result<(), Error> {
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
