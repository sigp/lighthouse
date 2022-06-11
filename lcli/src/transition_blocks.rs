//! # Transition Blocks
//!
//! Use this tool to apply a `SignedBeaconBlock` to a `BeaconState`. Useful for benchmarking or
//! Troubleshooting consensus failures.
//!
//! It can load states and blocks from file or pull them from a beaconAPI. Objects pulled from a
//! beaconAPI can be saved to disk to reduce future calls to that server.
//!
//! ## Examples
//!
//! ### Example 1.
//!
//! Download the 0x6c69 block and its pre-state (the state from its parent block) from the
//! beaconAPI. Advance the pre-state to the slot of the 0x6c69 and apply that block to the
//! pre-state.
//!
//! ```ignore
//! lcli transition-blocks \
//!     --beacon-url http://localhost:5052 \
//!     --block-id 0x6c69cf50a451f1ec905e954bf1fa22970f371a72a5aa9f8e3a43a18fdd980bec \
//!     --runs 10
//! ```
//!
//! ### Example 2.
//!
//! Download a block and pre-state to the filesystem, without performing any transitions:
//!
//! ```ignore
//! lcli transition-blocks \
//!     --beacon-url http://localhost:5052 \
//!     --block-id 0x6c69cf50a451f1ec905e954bf1fa22970f371a72a5aa9f8e3a43a18fdd980bec \
//!     --runs 0 \
//!     --block-output-path /tmp/block-0x6c69.ssz \
//!     --pre-state-output-path /tmp/pre-state-0x6c69.ssz
//! ```
//!
//! ### Example 3.
//!
//! Do one run over the block and pre-state downloaded in the previous example and save the post
//! state to file:
//!
//! ```ignore
//! lcli transition-blocks \
//!     --block-path /tmp/block-0x6c69.ssz \
//!     --pre-state-path /tmp/pre-state-0x6c69.ssz
//!     --post-state-output-path /tmp/post-state-0x6c69.ssz
//! ```
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{
    types::{BlockId, StateId},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use ssz::Encode;
use state_processing::{
    per_block_processing, per_slot_processing, BlockSignatureStrategy, VerifyBlockRoot,
};
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use types::{BeaconState, ChainSpec, CloneConfig, EthSpec, SignedBeaconBlock};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Config {
    signature_strategy: BlockSignatureStrategy,
    exclude_cache_builds: bool,
    exclude_post_block_thc: bool,
}

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let spec = &T::default_spec();
    let executor = env.core_context().executor.clone();

    let pre_state_path: Option<PathBuf> = parse_optional(matches, "pre-state-path")?;
    let block_path: Option<PathBuf> = parse_optional(matches, "block-path")?;
    let post_state_output_path: Option<PathBuf> =
        parse_optional(matches, "post-state-output-path")?;
    let pre_state_output_path: Option<PathBuf> = parse_optional(matches, "pre-state-output-path")?;
    let block_output_path: Option<PathBuf> = parse_optional(matches, "block-output-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;
    let no_signature_verification = matches.is_present("no-signature-verification");
    let config = Config {
        exclude_cache_builds: matches.is_present("exclude-cache-builds"),
        exclude_post_block_thc: matches.is_present("exclude-post-block-thc"),
        signature_strategy: if no_signature_verification {
            BlockSignatureStrategy::NoVerification
        } else {
            BlockSignatureStrategy::VerifyBulk
        },
    };

    info!("Using {} spec", T::spec_name());
    info!("Doing {} runs", runs);
    info!("{:?}", &config);

    let (mut pre_state, block) = match (pre_state_path, block_path, beacon_url) {
        (Some(pre_state_path), Some(block_path), None) => {
            info!("Block path: {:?}", pre_state_path);
            info!("Pre-state path: {:?}", block_path);
            let pre_state = load_from_ssz_with(&pre_state_path, spec, BeaconState::from_ssz_bytes)?;
            let block = load_from_ssz_with(&block_path, spec, SignedBeaconBlock::from_ssz_bytes)?;
            (pre_state, block)
        }
        (None, None, Some(beacon_url)) => {
            let block_id: BlockId = parse_required(matches, "block-id")?;
            let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
            executor
                .handle()
                .ok_or_else(|| "shut down in progress")?
                .block_on(async move {
                    let block = client
                        .get_beacon_blocks(block_id)
                        .await
                        .map_err(|e| format!("Failed to download block: {:?}", e))?
                        .ok_or_else(|| format!("Unable to locate block at {:?}", block_id))?
                        .data;

                    if block.slot() == spec.genesis_slot {
                        return Err("Cannot run on the genesis block".to_string());
                    }

                    let parent_block: SignedBeaconBlock<T> = client
                        .get_beacon_blocks(BlockId::Root(block.parent_root()))
                        .await
                        .map_err(|e| format!("Failed to download parent block: {:?}", e))?
                        .ok_or_else(|| format!("Unable to locate parent block at {:?}", block_id))?
                        .data;

                    let state_id = StateId::Root(parent_block.state_root());
                    let pre_state = client
                        .get_debug_beacon_states::<T>(state_id)
                        .await
                        .map_err(|e| format!("Failed to download state: {:?}", e))?
                        .ok_or_else(|| format!("Unable to locate state at {:?}", state_id))?
                        .data;

                    Ok((pre_state, block))
                })
                .map_err(|e| format!("Failed to complete task: {:?}", e))?
        }
        _ => {
            return Err(
                "must supply *both* --pre-state-path and --block-path *or* only --beacon-url"
                    .into(),
            )
        }
    };

    if config.exclude_cache_builds {
        pre_state
            .build_all_caches(spec)
            .map_err(|e| format!("Unable to build caches: {:?}", e))?;
        pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build THC: {:?}", e))?;
    }

    let mut output_post_state = None;

    for i in 0..runs {
        let pre_state = pre_state.clone_with(CloneConfig::all());
        let block = block.clone();

        let start = Instant::now();

        let post_state = do_transition(pre_state, block, &config, spec)?;

        let duration = Instant::now().duration_since(start);
        info!("Run {}: {:?}", i, duration);

        if output_post_state.is_none() {
            output_post_state = Some(post_state)
        }
    }

    if let Some(path) = post_state_output_path {
        let output_post_state = output_post_state.ok_or_else(|| {
            format!(
                "Post state was not computed, cannot save to disk (runs = {})",
                runs
            )
        })?;

        let mut output_file =
            File::create(path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

        output_file
            .write_all(&output_post_state.as_ssz_bytes())
            .map_err(|e| format!("Unable to write to output file: {:?}", e))?;
    }

    if let Some(path) = pre_state_output_path {
        let mut output_file =
            File::create(path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

        output_file
            .write_all(&pre_state.as_ssz_bytes())
            .map_err(|e| format!("Unable to write to output file: {:?}", e))?;
    }

    if let Some(path) = block_output_path {
        let mut output_file =
            File::create(path).map_err(|e| format!("Unable to create output file: {:?}", e))?;

        output_file
            .write_all(&block.as_ssz_bytes())
            .map_err(|e| format!("Unable to write to output file: {:?}", e))?;
    }

    Ok(())
}

fn do_transition<T: EthSpec>(
    mut pre_state: BeaconState<T>,
    block: SignedBeaconBlock<T>,
    config: &Config,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    if !config.exclude_cache_builds {
        let t = Instant::now();
        pre_state
            .build_all_caches(spec)
            .map_err(|e| format!("Unable to build caches: {:?}", e))?;
        debug!("Build caches: {}ms", t.elapsed().as_millis());

        let t = Instant::now();
        pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Initial tree hash: {}ms", t.elapsed().as_millis());
    }

    // Transition the parent state to the block slot.
    let t = Instant::now();
    for i in pre_state.slot().as_u64()..block.slot().as_u64() {
        per_slot_processing(&mut pre_state, None, spec)
            .map_err(|e| format!("Failed to advance slot on iteration {}: {:?}", i, e))?;
    }
    debug!("Slot processing: {}ms", t.elapsed().as_millis());

    let t = Instant::now();
    pre_state
        .update_tree_hash_cache()
        .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
    debug!("Pre-block tree hash: {}ms", t.elapsed().as_millis());

    let t = Instant::now();
    pre_state
        .build_all_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;
    debug!("Build all caches (again): {}ms", t.elapsed().as_millis());

    let t = Instant::now();
    per_block_processing(
        &mut pre_state,
        &block,
        None,
        config.signature_strategy,
        VerifyBlockRoot::True,
        spec,
    )
    .map_err(|e| format!("State transition failed: {:?}", e))?;
    debug!("Process block: {}ms", t.elapsed().as_millis());

    if !config.exclude_post_block_thc {
        let t = Instant::now();
        pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Post-block tree hash: {}ms", t.elapsed().as_millis());
    }

    Ok(pre_state)
}

pub fn load_from_ssz_with<T>(
    path: &Path,
    spec: &ChainSpec,
    decoder: impl FnOnce(&[u8], &ChainSpec) -> Result<T, ssz::DecodeError>,
) -> Result<T, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Unable to open file {:?}: {:?}", path, e))?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read from file {:?}: {:?}", path, e))?;
    let t = Instant::now();
    let result = decoder(&bytes, spec).map_err(|e| format!("Ssz decode failed: {:?}", e));
    debug!(
        "SSZ decoding {}: {}ms",
        path.display(),
        t.elapsed().as_millis()
    );
    result
}
