use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::error::Error;
use crate::cases::{LoadCase, Case};
use serde::Deserialize;
use std::path::Path;
use types::*;

#[derive(Debug)]
pub struct LightClientDataCollection<E: EthSpec> {
    pub initial_state: BeaconState<E>,
    pub steps: Vec<Step<E>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step<E: EthSpec> {
    NewBlock {
        block: SignedBeaconBlock<E>,
    },
    NewHead {
        block_id: String,
        checks: Checks,
    },
}

#[derive(Debug, Deserialize)]
pub struct Checks {
    pub latest_finality_update: Option<String>,
    pub latest_optimistic_update: Option<String>,
    pub bootstraps: Vec<(String, String)>,
    pub best_updates: Vec<(u64, String)>,
}

impl<E: EthSpec> LoadCase for LightClientDataCollection<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = fork_name.make_genesis_spec(E::default_spec());
        let initial_state = ssz_decode_state(
            &path.join("initial_state.ssz_snappy"),
            &spec
        )?;
        let steps_yaml: Vec<yaml_serde::Value> = yaml_decode_file(
            &path.join("steps.yaml")
        )?;
        let mut steps = vec![];
        for step in steps_yaml {
            if let Some(block_path) = step.get("new_block") {
                let block = ssz_decode_file_with(
                    &path.join(block_path.as_str().unwrap()),
                    |bytes| SignedBeaconBlock::from_ssz_bytes(bytes, &spec)
                )?;
                steps.push(Step::NewBlock { block });
            } else if step.get("new_head").is_some() {
            }
        }
        Ok(Self { initial_state, steps })
    }
}

impl<E: EthSpec> Case for LightClientDataCollection<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
	Err(Error::SkippedKnownFailure)
    }
}
