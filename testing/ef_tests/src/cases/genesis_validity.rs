use super::*;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use state_processing::is_valid_genesis_state;
use types::BeaconState;

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    #[serde(rename(deserialize = "description"))]
    _description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisValidity {
    pub metadata: Option<Metadata>,
    pub genesis: BeaconState,
    pub is_valid: bool,
}

impl LoadCase for GenesisValidity {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec(fork_name);
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

impl Case for GenesisValidity {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Base
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec(fork_name);

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
