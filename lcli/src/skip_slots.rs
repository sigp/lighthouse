use crate::transition_blocks::load_from_ssz_with;
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{types::StateId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use ssz::Encode;
use state_processing::state_advance::{complete_state_advance, partial_state_advance};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use types::{BeaconState, CloneConfig, EthSpec};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let spec = &T::default_spec();
    let executor = env.core_context().executor.clone();

    let output_path: Option<PathBuf> = parse_optional(matches, "output-path")?;
    let state_path: Option<PathBuf> = parse_optional(matches, "state-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;
    let slots: u64 = parse_required(matches, "slots")?;
    let partial: bool = matches.is_present("partial-state-advance");

    info!("Using {} spec", T::spec_name());
    info!("Advancing {} slots", slots);
    info!("Doing {} runs", runs);

    let mut state: BeaconState<T> = match (state_path, beacon_url) {
        (Some(state_path), None) => {
            info!("State path: {:?}", state_path);
            load_from_ssz_with(&state_path, spec, BeaconState::from_ssz_bytes)?
        }
        (None, Some(beacon_url)) => {
            let state_id: StateId = parse_required(matches, "state-id")?;
            let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
            executor
                .handle()
                .ok_or_else(|| "shut down in progress")?
                .block_on(async move {
                    client
                        .get_debug_beacon_states(state_id)
                        .await
                        .map_err(|e| format!("Failed to download state: {:?}", e))
                })
                .map_err(|e| format!("Failed to complete task: {:?}", e))?
                .ok_or_else(|| format!("Unable to locate state at {:?}", state_id))?
                .data
        }
        _ => return Err("mut supply either --state-file or --beacon-url".into()),
    };

    let initial_slot = state.slot();
    let target_slot = initial_slot + slots;

    state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    let state_root = state
        .update_tree_hash_cache()
        .map_err(|e| format!("Unable to build THC: {:?}", e))?;

    for i in 0..runs {
        let mut state = state.clone_with(CloneConfig::committee_caches_only());

        let start = Instant::now();

        if partial {
            partial_state_advance(&mut state, Some(state_root), target_slot, spec)
                .map_err(|e| format!("Unable to perform partial advance: {:?}", e))?;
        } else {
            complete_state_advance(&mut state, Some(state_root), target_slot, spec)
                .map_err(|e| format!("Unable to perform partial advance: {:?}", e))?;
        }

        let duration = Instant::now().duration_since(start);
        info!("Run {}: {:?}", i, duration);
    }

    if let Some(output_path) = output_path {
        let mut output_file = File::create(output_path)
            .map_err(|e| format!("Unable to create output file: {:?}", e))?;

        output_file
            .write_all(&state.as_ssz_bytes())
            .map_err(|e| format!("Unable to write to output file: {:?}", e))?;
    }

    Ok(())
}
