use super::*;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::is_valid_genesis_state;
use std::path::Path;
use types::{BeaconState, EthSpec, ForkName};

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct GenesisValidity<E: EthSpec> {
    pub metadata: Option<Metadata>,
    pub genesis: BeaconState<E>,
    pub is_valid: bool,
}

impl<E: EthSpec> LoadCase for GenesisValidity<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let genesis = ssz_decode_state(&path.join("genesis.ssz_snappy"), spec)?;
        let is_valid = yaml_decode_file(&path.join("is_valid.yaml"))?;
        let meta_path = path.join("meta.yaml");
        let metadata = if meta_path.exists() {
            Some(yaml_decode_file(&meta_path)?)
        } else {
            None
        };

        Ok(Self {
            metadata,
            genesis,
            is_valid,
        })
    }
}

impl<E: EthSpec> Case for GenesisValidity<E> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);

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
