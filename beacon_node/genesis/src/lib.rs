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

/// Provides a service that connects to some Eth1 HTTP JSON-RPC endpoint and maintains a cache of eth1
/// blocks and deposits, listening for the eth1 block that triggers eth2 genesis.
///
/// Is a wrapper around the `Service` struct of the `eth1` crate.
#[derive(Clone)]
pub struct Eth1GenesisService {
    /// The underlying service. Access to this object is only required for testing and diagnosis.
    pub core: Service,
    highest_processed_block: Arc<Mutex<Option<u64>>>,
}

impl Eth1GenesisService {
    /// Creates a new service. Does not attempt to connect to the Eth1 node.
    pub fn new(config: Eth1Config, log: Logger) -> Self {
        Self {
            core: Service::new(config, log),
            highest_processed_block: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a future that will keep updating the cache and resolve once it has discovered the
    /// first Eth1 block that triggers an Eth2 genesis.
    ///
    /// ## Returns
    ///
    /// - `Ok(state)` once the canonical eth2 genesis state has been discovered.
    /// - `Err(e)` if there is some internal error during updates.
    pub fn wait_for_genesis_state<E: EthSpec>(
        &self,
        update_interval: Duration,
        spec: ChainSpec,
    ) -> impl Future<Item = BeaconState<E>, Error = String> {
        let service = self.clone();
        let (exit_tx, exit_rx) = exit_future::signal();

        let loop_future = loop_fn::<(ChainSpec, Option<BeaconState<E>>), _, _, _>(
            (spec, None),
            move |(spec, state)| {
                let service = service.clone();

                Delay::new(Instant::now() + update_interval)
                    .map_err(|e| format!("Delay between genesis deposit checks failed: {:?}", e))
                    .and_then(move |()| {
                        if let Some(genesis_eth1_block) = service
                            .scan_new_blocks::<E>(&spec)
                            .map_err(|e| format!("Failed to scan for new blocks: {}", e))?
                        {
                            let genesis_state = service
                                .genesis_from_eth1_block(genesis_eth1_block, &spec)
                                .map_err(|e| {
                                    format!("Failed to generate valid genesis state : {}", e)
                                })?;

                            return Ok(Loop::Break((spec, genesis_state)));
                        }

                        Ok(Loop::Continue((spec, state)))
                    })
            },
        )
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

    /// Processes any new blocks that have appeared since this function was last run.
    ///
    /// A `highest_processed_block` value is stored in `self`. This function will find any blocks
    /// in it's caches that have a higher block number than `highest_processed_block` and check to
    /// see if they would trigger an Eth2 genesis.
    ///
    /// Blocks are always tested in increasing order, starting with the lowest unknown block
    /// number in the cache.
    ///
    /// ## Returns
    ///
    /// - `Ok(Some(eth1_block))` if a previously-unprocessed block would trigger Eth2 genesis.
    /// - `Ok(None)` if none of the new blocks would trigger genesis, or there were no new blocks.
    /// - `Err(_)` if there was some internal error.
    fn scan_new_blocks<E: EthSpec>(&self, spec: &ChainSpec) -> Result<Option<Eth1Block>, String> {
        Ok(self
            .core
            .blocks()
            .read()
            .iter()
            // It's only worth scanning blocks that have timestamps _after_ genesis time. It's
            // impossible for any other block to trigger genesis.
            .filter(|block| block.timestamp >= spec.min_genesis_time)
            // The block cache might be more recently updated than deposit cache. Restrict any
            // block numbers that are not known by all caches.
            .filter(|block| block.number <= self.highest_known_block().unwrap_or_else(|| 0))
            // Try to find
            .find(|block| {
                let mut highest_processed_block = self.highest_processed_block.lock();

                let next_new_block_number =
                    highest_processed_block.map(|n| n + 1).unwrap_or_else(|| 0);

                if block.number < next_new_block_number {
                    return false;
                }

                self.is_valid_genesis_eth1_block::<E>(block.clone(), &spec)
                    .and_then(|val| {
                        *highest_processed_block = Some(block.number);
                        Ok(val)
                    })
                    .unwrap_or_else(|_| {
                        error!(
                            self.core.log,
                            "Failed to detect if eth1 block triggers genesis";
                            "eth1_block_number" => block.number,
                            "eth1_block_hash" => format!("{}", block.hash),
                        );
                        false
                    })
            })
            .cloned())
    }

    /// Produces an eth2 genesis `BeaconState` from the given `eth1_block`.
    ///
    /// ## Returns
    ///
    /// - Ok(genesis_state) if all went well.
    /// - Err(e) if the given `eth1_block` was not a viable block to trigger genesis or there was
    /// an internal error.
    fn genesis_from_eth1_block<E: EthSpec>(
        &self,
        eth1_block: Eth1Block,
        spec: &ChainSpec,
    ) -> Result<BeaconState<E>, String> {
        let deposit_logs = self
            .core
            .deposits()
            .read()
            .cache
            .iter()
            .take_while(|log| log.block_number <= eth1_block.number)
            .map(|log| log.deposit_data.clone())
            .collect::<Vec<_>>();

        let genesis_state = initialize_beacon_state_from_eth1(
            eth1_block.hash,
            eth1_block.timestamp,
            genesis_deposits(deposit_logs, &spec),
            &spec,
        )
        .map_err(|e| format!("Unable to initialize genesis state: {:?}", e))?;

        if is_valid_genesis_state(&genesis_state, &spec) {
            Ok(genesis_state)
        } else {
            Err("Generated state was not valid.".to_string())
        }
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
