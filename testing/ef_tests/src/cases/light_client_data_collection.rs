use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::error::Error;
use crate::cases::{LoadCase, Case};
use serde::Deserialize;
use beacon_chain::test_utils::BeaconChainHarness;
use std::sync::Arc;
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
    	let spec = _fork_name.make_genesis_spec(E::default_spec());
    
    	let harness = BeaconChainHarness::builder(E::default())
        	.spec(spec.clone().into())
        	.genesis_state_ephemeral_store(self.initial_state.clone())
        	.mock_execution_layer()
        	.build();

    	for step in &self.steps {
        	match step {
            	Step::NewBlock { block } => {
                	let block_root = block.canonical_root();
                	let block_contents = (Arc::new(block.clone()), None);
                	harness.chain.task_executor.clone()
                    	.block_on_dangerous(
                        	harness.process_block_result(block_contents),
                        	"ef_tests_block_on"
                    )
                    .ok_or_else(|| Error::InternalError("runtime shutdown".into()))?
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
                harness.update_light_client_server_cache(
                    &harness.get_current_state(),
                    block.slot(),
                    block_root,
                );
            }
            Step::NewHead { block_id: _, checks: _ } => {
                // TODO: handle NewHead steps
                return Err(Error::SkippedKnownFailure);
            }
        }
    }

    Ok(())
}
}
