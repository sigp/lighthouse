//! # Skip-Slots
//!
//! Use this tool to process a `BeaconState` through empty slots. Useful for benchmarking or
//! troubleshooting consensus failures.
//!
//! It can load states from file or pull them from a beaconAPI. States pulled from a beaconAPI can
//! be saved to disk to reduce future calls to that server.
//!
//! ## Examples
//!
//! ### Example 1.
//!
//! Download a state from a HTTP endpoint and skip forward an epoch, twice (the initial state is
//! advanced 32 slots twice, rather than it being advanced 64 slots):
//!
//! ```ignore
//! lcli skip-slots \
//!     --beacon-url http://localhost:5052 \
//!     --state-id 0x3cdc33cd02713d8d6cc33a6dbe2d3a5bf9af1d357de0d175a403496486ff845e \\
//!     --slots 32 \
//!     --runs 2
//! ```
//!
//! ### Example 2.
//!
//! Download a state to a SSZ file (without modifying it):
//!
//! ```ignore
//! lcli skip-slots \
//!     --beacon-url http://localhost:5052 \
//!     --state-id 0x3cdc33cd02713d8d6cc33a6dbe2d3a5bf9af1d357de0d175a403496486ff845e \
//!     --slots 0 \
//!     --runs 0 \
//!     --output-path /tmp/state-0x3cdc.ssz
//! ```
//!
//! ### Example 3.
//!
//! Do two runs over the state that was downloaded in the previous example:
//!
//! ```ignore
//! lcli skip-slots \
//!     --pre-state-path /tmp/state-0x3cdc.ssz \
//!     --slots 32 \
//!     --runs 2
//! ```
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
use types::{BeaconState, CloneConfig, EthSpec, Hash256};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let spec = &T::default_spec();
    let executor = env.core_context().executor;

    let output_path: Option<PathBuf> = parse_optional(matches, "output-path")?;
    let state_path: Option<PathBuf> = parse_optional(matches, "pre-state-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;
    let slots: u64 = parse_required(matches, "slots")?;
    let cli_state_root: Option<Hash256> = parse_optional(matches, "state-root")?;
    let partial: bool = matches.is_present("partial-state-advance");

    info!("Using {} spec", T::spec_name());
    info!("Advancing {} slots", slots);
    info!("Doing {} runs", runs);

    let (mut state, state_root) = match (state_path, beacon_url) {
        (Some(state_path), None) => {
            info!("State path: {:?}", state_path);
            let state = load_from_ssz_with(&state_path, spec, BeaconState::from_ssz_bytes)?;
            (state, None)
        }
        (None, Some(beacon_url)) => {
            let state_id: StateId = parse_required(matches, "state-id")?;
            let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
            let state = executor
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
                .data;
            let state_root = match state_id {
                StateId::Root(root) => Some(root),
                _ => None,
            };
            (state, state_root)
        }
        _ => return Err("must supply either --state-path or --beacon-url".into()),
    };

    let initial_slot = state.slot();
    let target_slot = initial_slot + slots;

    state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;

    let state_root = if let Some(root) = cli_state_root.or(state_root) {
        root
    } else {
        state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build THC: {:?}", e))?
    };

    for i in 0..runs {
        let mut state = state.clone_with(CloneConfig::all());

        let start = Instant::now();

        if partial {
            partial_state_advance(&mut state, Some(state_root), target_slot, spec)
                .map_err(|e| format!("Unable to perform partial advance: {:?}", e))?;
        } else {
            complete_state_advance(&mut state, Some(state_root), target_slot, spec)
                .map_err(|e| format!("Unable to perform complete advance: {:?}", e))?;
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
