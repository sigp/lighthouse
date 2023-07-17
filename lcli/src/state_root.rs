use crate::transition_blocks::load_from_ssz_with;
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{types::StateId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use eth2_network_config::Eth2NetworkConfig;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use types::{BeaconState, EthSpec};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run<T: EthSpec>(
    env: Environment<T>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let executor = env.core_context().executor;

    let spec = &network_config.chain_spec::<T>()?;

    let state_path: Option<PathBuf> = parse_optional(matches, "state-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;

    info!(
        "Using {} network ({} spec)",
        spec.config_name.as_deref().unwrap_or("unknown"),
        T::spec_name()
    );
    info!("Doing {} runs", runs);

    let state = match (state_path, beacon_url) {
        (Some(state_path), None) => {
            info!("State path: {:?}", state_path);
            load_from_ssz_with(&state_path, spec, BeaconState::from_ssz_bytes)?
        }
        (None, Some(beacon_url)) => {
            let state_id: StateId = parse_required(matches, "state-id")?;
            let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
            executor
                .handle()
                .ok_or("shutdown in progress")?
                .block_on(async move {
                    client
                        .get_debug_beacon_states::<T>(state_id)
                        .await
                        .map_err(|e| format!("Failed to download state: {:?}", e))
                })
                .map_err(|e| format!("Failed to complete task: {:?}", e))?
                .ok_or_else(|| format!("Unable to locate state at {:?}", state_id))?
                .data
        }
        _ => return Err("must supply either --state-path or --beacon-url".into()),
    };

    /*
     * Perform the core "runs".
     */
    let mut state_root = None;
    for i in 0..runs {
        let mut state = state.clone();
        let timer = Instant::now();
        state_root = Some(
            state
                .update_tree_hash_cache()
                .map_err(|e| format!("error computing state root: {e:?}"))?,
        );
        info!("Run {}: {:?}", i, timer.elapsed());
    }

    if let Some(state_root) = state_root {
        info!("State root is {:?}", state_root);
    }
    Ok(())
}
