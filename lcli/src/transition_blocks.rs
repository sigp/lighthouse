//! # Transition Blocks
//!
//! Use this tool to apply a `SignedBeaconBlock` to a `BeaconState`. Useful for benchmarking or
//! troubleshooting consensus failures.
//!
//! It can load states and blocks from file or pull them from a beaconAPI. Objects pulled from a
//! beaconAPI can be saved to disk to reduce future calls to that server.
//!
//! Logging output is controlled via the `RUST_LOG` environment variable. For example, `export
//! RUST_LOG=debug`.
//!
//! ## Examples
//!
//! ### Run using a block from a beaconAPI
//!
//! Download the 0x6c69 block and its pre-state (the state from its parent block) from the
//! beaconAPI. Advance the pre-state to the slot of the 0x6c69 block and apply that block to the
//! pre-state.
//!
//! ```ignore
//! lcli transition-blocks \
//!     --beacon-url http://localhost:5052 \
//!     --block-id 0x6c69cf50a451f1ec905e954bf1fa22970f371a72a5aa9f8e3a43a18fdd980bec \
//!     --runs 10
//! ```
//!
//! ### Download a block and pre-state from a beaconAPI to the filesystem
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
//! ### Use a block and pre-state from the filesystem
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
//!
//! ### Isolate block processing for benchmarking
//!
//! Try to isolate block processing as much as possible for benchmarking:
//!
//! ```ignore
//! lcli transition-blocks \
//!     --block-path /tmp/block-0x6c69.ssz \
//!     --pre-state-path /tmp/pre-state-0x6c69.ssz \
//!     --runs 10 \
//!     --exclude-cache-builds \
//!     --exclude-post-block-thc
//! ```
use beacon_chain::{
    test_utils::EphemeralHarnessType, validator_pubkey_cache::ValidatorPubkeyCache,
};
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::{null_logger, Environment};
use eth2::{
    types::{BlockId, StateId},
    BeaconNodeHttpClient, SensitiveUrl, Timeouts,
};
use eth2_network_config::Eth2NetworkConfig;
use ssz::Encode;
use state_processing::state_advance::complete_state_advance;
use state_processing::{
    block_signature_verifier::BlockSignatureVerifier, per_block_processing, BlockSignatureStrategy,
    ConsensusContext, StateProcessingStrategy, VerifyBlockRoot,
};
use std::borrow::Cow;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::HotColdDB;
use types::{BeaconState, ChainSpec, CloneConfig, EthSpec, Hash256, SignedBeaconBlock};

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Config {
    no_signature_verification: bool,
    exclude_cache_builds: bool,
    exclude_post_block_thc: bool,
}

pub fn run<T: EthSpec>(
    env: Environment<T>,
    network_config: Eth2NetworkConfig,
    matches: &ArgMatches,
) -> Result<(), String> {
    let spec = &network_config.chain_spec::<T>()?;
    let executor = env.core_context().executor;

    /*
     * Parse (most) CLI arguments.
     */

    let pre_state_path: Option<PathBuf> = parse_optional(matches, "pre-state-path")?;
    let block_path: Option<PathBuf> = parse_optional(matches, "block-path")?;
    let post_state_output_path: Option<PathBuf> =
        parse_optional(matches, "post-state-output-path")?;
    let pre_state_output_path: Option<PathBuf> = parse_optional(matches, "pre-state-output-path")?;
    let block_output_path: Option<PathBuf> = parse_optional(matches, "block-output-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;
    let config = Config {
        no_signature_verification: matches.is_present("no-signature-verification"),
        exclude_cache_builds: matches.is_present("exclude-cache-builds"),
        exclude_post_block_thc: matches.is_present("exclude-post-block-thc"),
    };

    info!("Using {} spec", T::spec_name());
    info!("Doing {} runs", runs);
    info!("{:?}", &config);

    /*
     * Load the block and pre-state from disk or beaconAPI URL.
     */

    let (mut pre_state, mut state_root_opt, block) = match (pre_state_path, block_path, beacon_url)
    {
        (Some(pre_state_path), Some(block_path), None) => {
            info!("Block path: {:?}", block_path);
            info!("Pre-state path: {:?}", pre_state_path);
            let pre_state = load_from_ssz_with(&pre_state_path, spec, BeaconState::from_ssz_bytes)?;
            let block = load_from_ssz_with(&block_path, spec, SignedBeaconBlock::from_ssz_bytes)?;
            (pre_state, None, block)
        }
        (None, None, Some(beacon_url)) => {
            let block_id: BlockId = parse_required(matches, "block-id")?;
            let client = BeaconNodeHttpClient::new(beacon_url, Timeouts::set_all(HTTP_TIMEOUT));
            executor
                .handle()
                .ok_or("shutdown in progress")?
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

                    let state_root = parent_block.state_root();
                    let state_id = StateId::Root(state_root);
                    let pre_state = client
                        .get_debug_beacon_states::<T>(state_id)
                        .await
                        .map_err(|e| format!("Failed to download state: {:?}", e))?
                        .ok_or_else(|| format!("Unable to locate state at {:?}", state_id))?
                        .data;

                    Ok((pre_state, Some(state_root), block))
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

    // Compute the block root.
    let block_root = block.canonical_root();

    /*
     * Create a `BeaconStore` and `ValidatorPubkeyCache` for block signature verification.
     */

    let store = HotColdDB::open_ephemeral(
        <_>::default(),
        spec.clone(),
        null_logger().map_err(|e| format!("Failed to create null_logger: {:?}", e))?,
    )
    .map_err(|e| format!("Failed to create ephemeral store: {:?}", e))?;
    let store = Arc::new(store);

    debug!("Building pubkey cache (might take some time)");
    let validator_pubkey_cache = ValidatorPubkeyCache::new(&pre_state, store)
        .map_err(|e| format!("Failed to create pubkey cache: {:?}", e))?;

    /*
     * If cache builds are excluded from the timings, build them early so they are available for
     * each run.
     */

    if config.exclude_cache_builds {
        pre_state
            .build_caches(spec)
            .map_err(|e| format!("Unable to build caches: {:?}", e))?;
        let state_root = pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build THC: {:?}", e))?;

        if state_root_opt.map_or(false, |expected| expected != state_root) {
            return Err(format!(
                "State root mismatch! Expected {}, computed {}",
                state_root_opt.unwrap(),
                state_root
            ));
        }
        state_root_opt = Some(state_root);
    }

    /*
     * Perform the core "runs".
     */

    let mut output_post_state = None;
    for i in 0..runs {
        let pre_state = pre_state.clone_with(CloneConfig::all());
        let block = block.clone();

        let start = Instant::now();

        let post_state = do_transition(
            pre_state,
            block_root,
            block,
            state_root_opt,
            &config,
            &validator_pubkey_cache,
            spec,
        )?;

        let duration = Instant::now().duration_since(start);
        info!("Run {}: {:?}", i, duration);

        if output_post_state.is_none() {
            output_post_state = Some(post_state)
        }
    }

    /*
     * Write artifacts to disk, if required.
     */

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
    block_root: Hash256,
    block: SignedBeaconBlock<T>,
    mut state_root_opt: Option<Hash256>,
    config: &Config,
    validator_pubkey_cache: &ValidatorPubkeyCache<EphemeralHarnessType<T>>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, String> {
    if !config.exclude_cache_builds {
        let t = Instant::now();
        pre_state
            .build_caches(spec)
            .map_err(|e| format!("Unable to build caches: {:?}", e))?;
        debug!("Build caches: {:?}", t.elapsed());

        let t = Instant::now();
        let state_root = pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Initial tree hash: {:?}", t.elapsed());

        if state_root_opt.map_or(false, |expected| expected != state_root) {
            return Err(format!(
                "State root mismatch! Expected {}, computed {}",
                state_root_opt.unwrap(),
                state_root
            ));
        }
        state_root_opt = Some(state_root);
    }

    let state_root = state_root_opt.ok_or("Failed to compute state root, internal error")?;

    // Transition the parent state to the block slot.
    let t = Instant::now();
    complete_state_advance(&mut pre_state, Some(state_root), block.slot(), spec)
        .map_err(|e| format!("Unable to perform complete advance: {e:?}"))?;
    debug!("Slot processing: {:?}", t.elapsed());

    let t = Instant::now();
    pre_state
        .build_caches(spec)
        .map_err(|e| format!("Unable to build caches: {:?}", e))?;
    debug!("Build all caches (again): {:?}", t.elapsed());

    let mut ctxt = ConsensusContext::new(pre_state.slot())
        .set_current_block_root(block_root)
        .set_proposer_index(block.message().proposer_index());

    if !config.no_signature_verification {
        let get_pubkey = move |validator_index| {
            validator_pubkey_cache
                .get(validator_index)
                .map(Cow::Borrowed)
        };

        let decompressor = move |pk_bytes| {
            // Map compressed pubkey to validator index.
            let validator_index = validator_pubkey_cache.get_index(pk_bytes)?;
            // Map validator index to pubkey (respecting guard on unknown validators).
            get_pubkey(validator_index)
        };

        let t = Instant::now();
        BlockSignatureVerifier::verify_entire_block(
            &pre_state,
            get_pubkey,
            decompressor,
            &block,
            &mut ctxt,
            spec,
        )
        .map_err(|e| format!("Invalid block signature: {:?}", e))?;
        debug!("Batch verify block signatures: {:?}", t.elapsed());

        // Signature verification should prime the indexed attestation cache.
        assert_eq!(
            ctxt.num_cached_indexed_attestations(),
            block.message().body().attestations().len()
        );
    }

    let t = Instant::now();
    per_block_processing(
        &mut pre_state,
        &block,
        BlockSignatureStrategy::NoVerification,
        StateProcessingStrategy::Accurate,
        VerifyBlockRoot::True,
        &mut ctxt,
        spec,
    )
    .map_err(|e| format!("State transition failed: {:?}", e))?;
    debug!("Process block: {:?}", t.elapsed());

    if !config.exclude_post_block_thc {
        let t = Instant::now();
        pre_state
            .update_tree_hash_cache()
            .map_err(|e| format!("Unable to build tree hash cache: {:?}", e))?;
        debug!("Post-block tree hash: {:?}", t.elapsed());
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
    debug!("SSZ decoding {}: {:?}", path.display(), t.elapsed());
    result
}
