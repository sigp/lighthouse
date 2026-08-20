use crate::cases::{Case, LoadCase};
use crate::decode::{ssz_decode_file_with, ssz_decode_state, yaml_decode_file};
use crate::error::Error;
use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::BeaconChainHarness;
use beacon_chain::{ChainConfig, NotifyExecutionLayer};
use bls::Signature;
use serde::Deserialize;
use slot_clock::{SlotClock, TestingSlotClock};
use std::path::{Path, PathBuf};
use ssz::Encode;
use std::sync::Arc;
use std::time::Duration;
use types::BlockImportSource;
use types::*;

#[derive(Debug)]
pub struct LightClientDataCollection<E: EthSpec> {
    pub path: PathBuf,
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
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Altair))
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Bellatrix))
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Capella))
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Deneb))
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Electra))
                        .or_else(|_| SignedBeaconBlock::from_ssz_bytes_by_fork(bytes, ForkName::Fulu))
                })?;
                steps.push(Step::NewBlock { block: Box::new(block) });
            } else if let Some(new_head) = step.new_head {
                let latest_finality_update = new_head.checks.latest_finality_update
                    .map(|fd| format!("{}.ssz_snappy", fd.data));
                let latest_optimistic_update = new_head.checks.latest_optimistic_update
                    .map(|fd| format!("{}.ssz_snappy", fd.data));
                let bootstraps = new_head.checks.bootstraps.into_iter()
                    .filter_map(|b| b.bootstrap.map(|fd| (b.block_root, format!("{}.ssz_snappy", fd.data))))
                    .collect();
                let best_updates = new_head.checks.best_updates.into_iter()
                    .filter_map(|u| u.update.map(|fd| (u.period, format!("{}.ssz_snappy", fd.data))))
                    .collect();
                steps.push(Step::NewHead {
                    block_id: new_head.head_block_root,
                    checks: Checks { latest_finality_update, latest_optimistic_update, bootstraps, best_updates },
                });
            }
        }
        Ok(Self { path: path.to_path_buf(), initial_state, steps })
    }
}

impl<E: EthSpec> Case for LightClientDataCollection<E> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let mut spec = fork_name.make_genesis_spec(E::default_spec());
        if fork_name.bellatrix_enabled() { spec.bellatrix_fork_epoch = Some(Epoch::new(0)); }
        if fork_name.capella_enabled() { spec.capella_fork_epoch = Some(Epoch::new(0)); }
        if fork_name.deneb_enabled() { spec.deneb_fork_epoch = Some(Epoch::new(0)); }
        if fork_name.electra_enabled() { spec.electra_fork_epoch = Some(Epoch::new(0)); }
        if fork_name.fulu_enabled() { spec.fulu_fork_epoch = Some(Epoch::new(0)); }

        let mut initial_state_mut = self.initial_state.clone();
        let _genesis_block = {
            let mut block = state_processing::genesis::genesis_block(&initial_state_mut, &spec)
                .map_err(|e| Error::FailedToParseTest(format!("genesis block: {:?}", e)))?;
            *block.state_root_mut() = initial_state_mut
                .update_tree_hash_cache()
                .map_err(|e| Error::FailedToParseTest(format!("hash state: {:?}", e)))?;
            SignedBeaconBlock::from_block(block, Signature::empty())
        };

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone().into())
            .keypairs(vec![])
            .chain_config(ChainConfig { archive: true, ..ChainConfig::default() })
            .genesis_state_ephemeral_store(self.initial_state.clone())
            .mock_execution_layer()
            .recalculate_fork_times_with_genesis(0)
            .node_custody_type(NodeCustodyType::Supernode)
            .mock_execution_layer_all_payloads_valid()
            .testing_slot_clock(slot_clock)
            .build();

        harness.chain.canonical_head
            .fork_choice_write_lock()
            .proto_array_mut()
            .set_prune_threshold(usize::MAX);

        for step in &self.steps {
            match step {
                Step::NewBlock { block } => {
                    harness.set_current_slot(block.slot());
                    let block_root = block.canonical_root();
                    let lookup_block = LookupBlock::new(Arc::new(block.as_ref().clone()));
                    harness.chain.task_executor.clone()
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
			    let _ = harness.chain.light_client_server_cache
			        .recompute_and_cache_updates(
			            harness.chain.store.clone(),
			            block.slot(),
			            &block.parent_root(),
			            sync_aggregate,
			            &spec,
			        );
			}
		}
                Step::NewHead { block_id, checks } => {

		    harness.chain.light_client_server_cache.reset_cache();
		    let _ = harness.chain.store.delete_light_client_update(0);
    		    let head_root = Hash256::from_slice(
			&hex::decode(block_id.trim_start_matches("0x"))
		        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?

		    );
		    let mut chain = vec![];
		    let mut current = head_root;
		    loop {
			if let Ok(Some(block)) = harness.chain.store.get_blinded_block(&current) {
			    let parent = block.parent_root();
			    chain.push(block);
			    if current == harness.chain.genesis_block_root {
			        break;
			    }
			    current = parent;
			} else {
			    break;
			}
		    }
		    chain.reverse(); // oldest first
		    for block in &chain {
	   	        if let Ok(sync_aggregate) = block.message().body().sync_aggregate() {
        	    	    let _ = harness.chain.light_client_server_cache
        		        .recompute_and_cache_updates(
			            harness.chain.store.clone(),
			            block.slot(),
			            &block.parent_root(),
		                    sync_aggregate,
		                    &spec,
		                );
		        }
		    }			




  		    if let Ok(Some(head_block)) = harness.chain.store.get_blinded_block(&head_root) {
  		        if let Ok(sync_aggregate) = head_block.message().body().sync_aggregate() {
  	       	            let _ = harness.chain.light_client_server_cache
  			        .recompute_and_cache_updates(
   			            harness.chain.store.clone(),
    		                    head_block.slot(),
    		                    &head_block.parent_root(),
    		                    sync_aggregate,
  		                    &spec,
    		                );
    			}
    		    }


                    harness.chain.task_executor.clone()
                        .block_on_dangerous(
                            harness.chain.recompute_head_at_current_slot(),
                            "ef_tests_block_on",
                        )
                        .ok_or_else(|| Error::InternalError("runtime shutdown".into()))?;

                    if let Some(expected_path) = &checks.latest_finality_update {
                        let expected = ssz_decode_file_with(
                            &self.path.join(expected_path),
                            |bytes| LightClientFinalityUpdate::from_ssz_bytes(bytes, fork_name),
                        )?;
                        let actual = harness.chain.light_client_server_cache.get_latest_finality_update();
                        let expected_clone = expected.clone();
			if actual != Some(expected_clone) {
			    eprintln!("DEBUG actual sig_slot bytes: {}", hex::encode(&actual.as_ref().map(|a| a.as_ssz_bytes()).unwrap_or_default()[516..524]));
			    eprintln!("DEBUG expected sig_slot bytes: {}", hex::encode(&expected.as_ssz_bytes()[516..524]));
			    eprintln!("DEBUG actual_is_some={} expected_path={}", actual.is_some(), expected_path);
			
                            return Err(Error::NotEqual("latest_finality_update mismatch".into()));
                        }
                    }

                    if let Some(expected_path) = &checks.latest_optimistic_update {
                        let expected = ssz_decode_file_with(
                            &self.path.join(expected_path),
                            |bytes| LightClientOptimisticUpdate::from_ssz_bytes(bytes, fork_name),
                        )?;
                        let actual = harness.chain.light_client_server_cache.get_latest_optimistic_update();
			let expected_clone = expected.clone();
                        if actual != Some(expected_clone) {
			    eprintln!("DEBUG opt actual_is_some={}", actual.is_some());
			    if let Some(ref a) = actual {
			        eprintln!("DEBUG opt actual_sig_slot: {}", hex::encode(&a.as_ssz_bytes()[a.as_ssz_bytes().len()-8..]));
			    }
			    eprintln!("DEBUG opt expected_sig_slot: {}", hex::encode(&expected.as_ssz_bytes()[expected.as_ssz_bytes().len()-8..]));

                            return Err(Error::NotEqual("latest_optimistic_update mismatch".into()));
                        }
                    }

                    for (block_root_str, expected_path) in &checks.bootstraps {
                        let block_root = Hash256::from_slice(
                            &hex::decode(block_root_str.trim_start_matches("0x"))
                                .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?
                        );
                        let actual = harness.chain
                            .get_light_client_bootstrap(&block_root)
                            .ok()
                            .flatten()
                            .map(|(b, _)| b);
                        if actual.is_some() {
                            let expected = ssz_decode_file_with(
                                &self.path.join(expected_path),
                                |bytes| LightClientBootstrap::from_ssz_bytes(bytes, fork_name),
                            )?;
                            if actual != Some(expected) {
                                return Err(Error::NotEqual(format!("bootstrap mismatch for {}", block_root_str)));
                            }
                        }
                    }

                    for (period, expected_path) in &checks.best_updates {
			eprintln!("DEBUG best_update checking period={} expected={}", period, expected_path);
                        let updates = harness.chain
                            .get_light_client_updates(*period, 1)
                            .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
			eprintln!("DEBUG best_update actual_count={}", updates.len());
                        let actual = updates.into_iter().next();
			if let Some(ref a) = actual {
			    use ssz::Encode;
			    eprintln!("DEBUG best_update actual sig_slot bytes: {}", hex::encode(&a.as_ssz_bytes()[a.as_ssz_bytes().len()-8..]));
			}
                        let expected = ssz_decode_file_with(
                            &self.path.join(expected_path),
                            |bytes| LightClientUpdate::from_ssz_bytes(bytes, &fork_name),
                        )?;
                        if actual.as_ref() != Some(&expected) {
                            return Err(Error::NotEqual(format!("best_update mismatch for period {}", period)));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
