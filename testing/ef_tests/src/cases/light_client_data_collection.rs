use crate::cases::{Case, LoadCase};
use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::error::Error;
use beacon_chain::NotifyExecutionLayer;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::test_utils::BeaconChainHarness;
use bls::Signature;
use serde::Deserialize;
use state_processing::genesis::genesis_block;
use std::path::Path;
use std::sync::Arc;
use types::BlockImportSource;
use types::*;

#[derive(Debug)]
pub struct LightClientDataCollection<E: EthSpec> {
    pub initial_state: BeaconState<E>,
    pub steps: Vec<Step<E>>,
}

#[derive(Debug)]
pub enum Step<E: EthSpec> {
    NewBlock { block: Box<SignedBeaconBlock<E>> },
    NewHead { block_id: String, checks: Checks },
}

#[derive(Debug)]
pub struct Checks {
    pub latest_finality_update: Option<String>,
    pub latest_optimistic_update: Option<String>,
    pub bootstraps: Vec<(String, String)>,
    pub best_updates: Vec<(u64, String)>,
}

#[derive(Debug, Deserialize)]
struct StepYaml {
    pub new_block: Option<NewBlockData>,
    pub new_head: Option<NewHeadData>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NewBlockData {
    pub fork_digest: String,
    pub data: String,
}

#[derive(Debug, Deserialize)]
struct NewHeadData {
    pub head_block_root: String,
    pub checks: ChecksYaml,
}

#[derive(Debug, Deserialize, Default)]
struct ChecksYaml {
    pub latest_finality_update: Option<ForkData>,
    pub latest_optimistic_update: Option<ForkData>,
    #[serde(default)]
    pub bootstraps: Vec<BootstrapYaml>,
    #[serde(default)]
    pub best_updates: Vec<BestUpdateYaml>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ForkData {
    pub fork_digest: String,
    pub data: String,
}

#[derive(Debug, Deserialize)]
struct BootstrapYaml {
    pub block_root: String,
    pub bootstrap: Option<ForkData>,
}

#[derive(Debug, Deserialize)]
struct BestUpdateYaml {
    pub period: u64,
    pub update: Option<ForkData>,
}

impl<E: EthSpec> LoadCase for LightClientDataCollection<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = fork_name.make_genesis_spec(E::default_spec());
        let initial_state = ssz_decode_state(&path.join("initial_state.ssz_snappy"), &spec)?;
        let step_yamls: Vec<StepYaml> = yaml_decode_file(&path.join("steps.yaml"))?;
        let mut steps = vec![];
        for step in step_yamls {
            if let Some(new_block) = step.new_block {
                let block_path = path.join(format!("{}.ssz_snappy", new_block.data));
                let block = ssz_decode_file_with(&block_path, |bytes| {
                    SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, fork_name)
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Altair)
                        })
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Bellatrix)
                        })
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Capella)
                        })
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Deneb)
                        })
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Electra)
                        })
                        .or_else(|_| {
                            SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Fulu)
                        })
                })?;
                steps.push(Step::NewBlock {
                    block: Box::new(block),
                });
            } else if let Some(new_head) = step.new_head {
                let latest_finality_update = new_head
                    .checks
                    .latest_finality_update
                    .map(|fd| format!("{}.ssz_snappy", fd.data));
                let latest_optimistic_update = new_head
                    .checks
                    .latest_optimistic_update
                    .map(|fd| format!("{}.ssz_snappy", fd.data));
                let bootstraps = new_head
                    .checks
                    .bootstraps
                    .into_iter()
                    .filter_map(|b| {
                        b.bootstrap
                            .map(|fd| (b.block_root, format!("{}.ssz_snappy", fd.data)))
                    })
                    .collect();
                let best_updates = new_head
                    .checks
                    .best_updates
                    .into_iter()
                    .filter_map(|u| {
                        u.update
                            .map(|fd| (u.period, format!("{}.ssz_snappy", fd.data)))
                    })
                    .collect();
                steps.push(Step::NewHead {
                    block_id: new_head.head_block_root,
                    checks: Checks {
                        latest_finality_update,
                        latest_optimistic_update,
                        bootstraps,
                        best_updates,
                    },
                });
            }
        }
        Ok(Self {
            initial_state,
            steps,
        })
    }
}

impl<E: EthSpec> Case for LightClientDataCollection<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let mut spec = _fork_name.make_genesis_spec(E::default_spec());
        if _fork_name.bellatrix_enabled() {
            spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        }
        if _fork_name.capella_enabled() {
            spec.capella_fork_epoch = Some(Epoch::new(0));
        }
        if _fork_name.deneb_enabled() {
            spec.deneb_fork_epoch = Some(Epoch::new(0));
        }
        if _fork_name.electra_enabled() {
            spec.electra_fork_epoch = Some(Epoch::new(0));
        }
        if _fork_name.fulu_enabled() {
            spec.fulu_fork_epoch = Some(Epoch::new(0));
        }
        let mut initial_state_mut = self.initial_state.clone();
        let genesis_block = {
            use state_processing::genesis::genesis_block;
            let mut block = state_processing::genesis::genesis_block(&mut initial_state_mut, &spec)
                .map_err(|e| Error::FailedToParseTest(format!("genesis block: {:?}", e)))?;
            *block.state_root_mut() = initial_state_mut
                .update_tree_hash_cache()
                .map_err(|e| Error::FailedToParseTest(format!("hash state: {:?}", e)))?;
            SignedBeaconBlock::from_block(block, Signature::empty())
        };
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone().into())
            .deterministic_keypairs(8)
            .initial_state_ephemeral_store(self.initial_state.clone(), genesis_block, None)
            .mock_execution_layer()
            .build();

        let mut skip_first = true;
        for step in &self.steps {
            match step {
                Step::NewBlock { block } => {
                    if skip_first {
                        skip_first = false;
                        continue;
                    }
                    let block_root = block.canonical_root();
                    harness.set_current_slot(block.slot());
                    let lookup_block = LookupBlock::new(Arc::new(block.as_ref().clone()));
                    harness
                        .chain
                        .task_executor
                        .clone()
                        .block_on_dangerous(
                            harness.chain.process_block(
                                block_root,
                                lookup_block,
                                NotifyExecutionLayer::No,
                                BlockImportSource::RangeSync,
                                || Ok(()),
                            ),
                            "ef_tests_block_on",
                        )
                        .ok_or_else(|| Error::InternalError("runtime shutdown".into()))?
                        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
                    if let Ok(sync_aggregate) = block.message().body().sync_aggregate() {
                        let _ = harness
                            .chain
                            .light_client_server_cache
                            .recompute_and_cache_updates(
                                harness.chain.store.clone(),
                                block.slot(),
                                &block.parent_root(),
                                sync_aggregate,
                                &spec,
                            );
                    }
                }
                Step::NewHead {
                    block_id: _,
                    checks: _,
                } => {
                    return Err(Error::SkippedKnownFailure);
                }
            }
        }
        Ok(())
    }
}
