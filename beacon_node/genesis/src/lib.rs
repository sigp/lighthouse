pub mod interop;

use eth1::{DepositSet, Eth1Block, GenesisService};
use futures::{
    future::{loop_fn, Loop},
    Future,
};
use parking_lot::Mutex;
use ssz::Decode;
use state_processing::{
    initialize_beacon_state_from_eth1, is_valid_genesis_state,
    per_block_processing::process_deposit,
};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use types::{BeaconState, ChainSpec, Deposit, Eth1Data, EthSpec, Hash256};

/// Load a `BeaconState` from the given `path`. The file should contain raw SSZ bytes (i.e., no
/// ASCII encoding or schema).
pub fn wait_for_eth1_genesis_state<E: EthSpec>(
    service: GenesisService,
    update_interval: Duration,
    spec: ChainSpec,
) -> impl Future<Item = BeaconState<E>, Error = String> {
    let next_block: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));

    // TODO: allow for exit on Ctrl+C.
    loop_fn((spec, 0_u64), move |(spec, state)| {
        let service = service.clone();
        let next_block = next_block.clone();

        let min_genesis_time = Duration::from_secs(spec.min_genesis_time);

        Delay::new(Instant::now() + update_interval)
            .map_err(|e| format!("Delay between genesis deposit checks failed: {:?}", e))
            .and_then(move |()| {
                let genesis_eth1_block = service
                    .core
                    .blocks()
                    .read()
                    .iter()
                    .filter(move |block| Duration::from_secs(block.timestamp) >= min_genesis_time)
                    .filter(|block| {
                        next_block
                            .lock()
                            .map(|next| block.number >= next)
                            .unwrap_or_else(|| true)
                    })
                    .find(|block| {
                        (*next_block.lock()) = Some(block.number + 1);

                        is_valid_genesis_eth1_block::<E>(service.clone(), block, &spec)
                            // TODO: log an error
                            .unwrap_or_else(|_| false)
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
                            .cloned()
                            .collect();

                        let (generated_deposit_root, deposits) = DepositSet::from_logs(
                            spec.deposit_contract_tree_depth as usize,
                            deposit_logs,
                        )
                        .into_components();

                        if Some(generated_deposit_root) != genesis_eth1_block.deposit_root {
                            return Err(
                                "The block deposit root does not match the locally generated one"
                                    .to_string(),
                            );
                        }

                        let genesis_state = initialize_beacon_state_from_eth1(
                            genesis_eth1_block.hash,
                            genesis_eth1_block.timestamp,
                            deposits,
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
}

/// A cheap (compared to using `initialize_beacon_state_from_eth1) method for determining if some
/// `target_block` will trigger genesis.
fn is_valid_genesis_eth1_block<E: EthSpec>(
    service: GenesisService,
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

        service
            .deposit_logs_at_block(target_block.number)
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

        Ok(is_valid_genesis_state(&local_state, spec))
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
