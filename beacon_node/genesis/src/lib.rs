pub mod interop;

pub use eth1::Config as Eth1Config;

use eth1::{DepositLog, Eth1Block, Service};
use exit_future;
use futures::{
    future::{loop_fn, Loop},
    Future,
};
use merkle_proof::MerkleTree;
use parking_lot::Mutex;
use rayon::prelude::*;
use slog::{error, Logger};
use ssz::Decode;
use state_processing::{
    initialize_beacon_state_from_eth1, is_valid_genesis_state,
    per_block_processing::process_deposit, process_activations,
};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use tree_hash::TreeHash;
use types::{BeaconState, ChainSpec, Deposit, DepositData, Eth1Data, EthSpec, Hash256};

#[derive(Clone)]
pub struct Eth1GenesisService {
    pub core: Service,
}

impl Eth1GenesisService {
    pub fn new(config: Eth1Config, log: Logger) -> Self {
        Self {
            core: Service::new(config, log),
        }
    }

    pub fn wait_for_genesis_state<E: EthSpec>(
        &self,
        update_interval: Duration,
        spec: ChainSpec,
    ) -> impl Future<Item = BeaconState<E>, Error = String> {
        let service = self.clone();
        let next_block: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
        let (exit_tx, exit_rx) = exit_future::signal();

        // TODO: allow for exit on Ctrl+C.
        let loop_future = loop_fn((spec, 0_u64), move |(spec, state)| {
            let service = service.clone();
            let next_block = next_block.clone();

            let min_genesis_time = Duration::from_secs(spec.min_genesis_time);

            Delay::new(Instant::now() + update_interval)
                .map_err(|e| format!("Delay between genesis deposit checks failed: {:?}", e))
                .and_then(move |()| {
                    let highest_known_block = service.highest_known_block();
                    let genesis_eth1_block = service
                        .core
                        .blocks()
                        .read()
                        .iter()
                        .filter(move |block| {
                            Duration::from_secs(block.timestamp) >= min_genesis_time
                        })
                        // Filter out blocks that are not yet known by the deposit updater.
                        .filter(|block| {
                            highest_known_block
                                .map(|n| n >= block.number)
                                .unwrap_or_else(|| false)
                        })
                        .filter(|block| {
                            next_block
                                .lock()
                                .map(|next| block.number >= next)
                                .unwrap_or_else(|| true)
                        })
                        .find(|block| {
                            let mut next_block = next_block.lock();

                            let new = next_block
                                .map(|next| block.number >= next)
                                .unwrap_or_else(|| true);

                            if new {
                                *next_block = Some(block.number + 1);

                                service
                                    .is_valid_genesis_eth1_block::<E>(block.clone(), &spec)
                                    .unwrap_or_else(|_| {
                                        error!(
                                            service.core.log,
                                            "Failed to detect if eth1 block triggers genesis";
                                            "eth1_block_number" => block.number,
                                            "eth1_block_hash" => format!("{}", block.hash),
                                        );
                                        false
                                    })
                            } else {
                                false
                            }
                        })
                        .cloned();

                    match genesis_eth1_block {
                        None => Ok(Loop::Continue((spec, state))),
                        Some(genesis_eth1_block) => {
                            let deposit_logs = service
                                .core
                                .deposits()
                                .read()
                                .cache
                                .iter()
                                .take_while(|log| log.block_number <= genesis_eth1_block.number)
                                .map(|log| log.deposit_data.clone())
                                .collect::<Vec<_>>();

                            let genesis_state = initialize_beacon_state_from_eth1(
                                genesis_eth1_block.hash,
                                genesis_eth1_block.timestamp,
                                genesis_deposits(deposit_logs, &spec),
                                &spec,
                            )
                            .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

                            if !is_valid_genesis_state(&genesis_state, &spec) {
                                return Err("Failed to generate a valid genesis state".to_string());
                            }

                            Ok(Loop::Break((spec, genesis_state)))
                        }
                    }
                })
        })
        .map(|(_spec, state)| state)
        .then(|v| {
            exit_tx.fire();
            v
        });

        let update_future = self
            .core
            .auto_update(update_interval, exit_rx)
            .map_err(|_| "Auto update failed".to_string());

        update_future.join(loop_future).map(|(_, state)| state)
    }

    /// A cheap (compared to using `initialize_beacon_state_from_eth1) method for determining if some
    /// `target_block` will trigger genesis.
    fn is_valid_genesis_eth1_block<E: EthSpec>(
        &self,
        target_block: &Eth1Block,
        spec: &ChainSpec,
    ) -> Result<bool, String> {
        if target_block.timestamp < spec.min_genesis_time {
            Ok(false)
        } else {
            let mut local_state: BeaconState<E> = BeaconState::new(
                0,
                Eth1Data {
                    block_hash: Hash256::zero(),
                    deposit_root: Hash256::zero(),
                    deposit_count: 0,
                },
                &spec,
            );

            local_state.genesis_time = target_block.timestamp;

            self.deposit_logs_at_block(target_block.number)
                .iter()
                // TODO: add the signature field back.
                //.filter(|deposit_log| deposit_log.signature_is_valid)
                .map(|deposit_log| Deposit {
                    proof: vec![Hash256::zero(); spec.deposit_contract_tree_depth as usize].into(),
                    data: deposit_log.deposit_data.clone(),
                })
                .try_for_each(|deposit| {
                    // No need to verify proofs in order to test if some block will trigger genesis.
                    const PROOF_VERIFICATION: bool = false;

                    process_deposit(
                        &mut local_state,
                        &deposit,
                        spec,
                        PROOF_VERIFICATION,
                        // TODO: disable signature verification
                    )
                    .map_err(|e| format!("Error whilst processing deposit: {:?}", e))
                })?;

            process_activations(&mut local_state, spec);

            Ok(is_valid_genesis_state(&local_state, spec))
        }
    }

    /// Returns the `block_number` of the highest (by block number) block in the cache.
    ///
    /// Takes the lower block number of the deposit and block caches to ensure this number is safe.
    fn highest_known_block(&self) -> Option<u64> {
        let block_cache = self.core.blocks().read().highest_block_number()?;
        let deposit_cache = self.core.deposits().read().last_processed_block?;

        Some(std::cmp::min(block_cache, deposit_cache))
    }

    /// Returns all deposit logs included in `block_number` and all prior blocks.
    fn deposit_logs_at_block(&self, block_number: u64) -> Vec<DepositLog> {
        self.core
            .deposits()
            .read()
            .cache
            .iter()
            .take_while(|log| log.block_number <= block_number)
            .cloned()
            .collect()
    }
}

/// Load a `BeaconState` from the given `path`. The file should contain raw SSZ bytes (i.e., no
/// ASCII encoding or schema).
pub fn state_from_ssz_file<E: EthSpec>(path: PathBuf) -> Result<BeaconState<E>, String> {
    File::open(path.clone())
        .map_err(move |e| format!("Unable to open SSZ genesis state file {:?}: {:?}", path, e))
        .and_then(|mut file| {
            let mut bytes = vec![];
            file.read_to_end(&mut bytes)
                .map_err(|e| format!("Failed to read SSZ file: {:?}", e))?;
            Ok(bytes)
        })
        .and_then(|bytes| {
            BeaconState::from_ssz_bytes(&bytes)
                .map_err(|e| format!("Unable to parse SSZ genesis state file: {:?}", e))
        })
}

/// Accepts the genesis block validator `DepositData` list and produces a list of `Deposit`, with
/// proofs.
fn genesis_deposits(deposit_data: Vec<DepositData>, spec: &ChainSpec) -> Vec<Deposit> {
    let deposit_root_leaves = deposit_data
        .par_iter()
        .map(|data| Hash256::from_slice(&data.tree_hash_root()))
        .collect::<Vec<_>>();

    let mut proofs = vec![];
    for i in 1..=deposit_root_leaves.len() {
        // Note: this implementation is not so efficient.
        //
        // If `MerkleTree` had a push method, we could just build one tree and sample it instead of
        // rebuilding the tree for each deposit.
        let tree = MerkleTree::create(
            &deposit_root_leaves[0..i],
            spec.deposit_contract_tree_depth as usize,
        );

        let (_, mut proof) = tree.generate_proof(i - 1, spec.deposit_contract_tree_depth as usize);
        proof.push(Hash256::from_slice(&int_to_bytes32(i)));

        assert_eq!(
            proof.len(),
            spec.deposit_contract_tree_depth as usize + 1,
            "Deposit proof should be correct len"
        );

        proofs.push(proof);
    }

    deposit_data
        .into_iter()
        .zip(proofs.into_iter())
        .map(|(data, proof)| (data, proof.into()))
        .map(|(data, proof)| Deposit { proof, data })
        .collect()
}

/// Returns `int` as little-endian bytes with a length of 32.
fn int_to_bytes32(int: usize) -> Vec<u8> {
    let mut vec = int.to_le_bytes().to_vec();
    vec.resize(32, 0);
    vec
}
