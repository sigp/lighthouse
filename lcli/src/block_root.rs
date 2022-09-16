//! # Block Root
//!
//! Use this tool to compute the canonical root of a `SignedBeaconBlock`. This is most likely only
//! useful for benchmarking with tools like `flamegraph`.
//!
//! It can load a block from a SSZ file or download it from a beaconAPI.
//!
//! Logging output is controlled via the `RUST_LOG` environment variable. For example, `export
//! RUST_LOG=debug`.
//!
//! ## Examples
//!
//! Download a block and re-compute the canonical root 5,000 times.
//!
//! ```ignore
//! lcli block-root \
//!     --beacon-url http://localhost:5052 \
//!     --block-id 0x3d887d30ee25c9c1ce7621ec30a7b49b07d6a03200df9c7206faca52a533f432 \
//!     --runs 5000
//! ```
//!
//! Load a block from SSZ and compute the canonical root once.
//!
//! ```ignore
//! lcli block-root \
//!     --block-path /tmp/block.ssz \
//!     --runs 1
//! ```
use crate::transition_blocks::load_from_ssz_with;
use clap::ArgMatches;
use clap_utils::{parse_optional, parse_required};
use environment::Environment;
use eth2::{types::BlockId, BeaconNodeHttpClient, SensitiveUrl, Timeouts};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use types::{EthSpec, FullPayload, SignedBeaconBlock};

const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let spec = &T::default_spec();
    let executor = env.core_context().executor;

    /*
     * Parse (most) CLI arguments.
     */

    let block_path: Option<PathBuf> = parse_optional(matches, "block-path")?;
    let beacon_url: Option<SensitiveUrl> = parse_optional(matches, "beacon-url")?;
    let runs: usize = parse_required(matches, "runs")?;

    info!("Using {} spec", T::spec_name());
    info!("Doing {} runs", runs);

    /*
     * Load the block and pre-state from disk or beaconAPI URL.
     */

    let block: SignedBeaconBlock<T, FullPayload<T>> = match (block_path, beacon_url) {
        (Some(block_path), None) => {
            info!("Block path: {:?}", block_path);
            load_from_ssz_with(&block_path, spec, SignedBeaconBlock::from_ssz_bytes)?
        }
        (None, Some(beacon_url)) => {
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
                    Ok::<_, String>(block)
                })
                .map_err(|e| format!("Failed to complete task: {:?}", e))?
        }
        _ => return Err("must supply --block-path *or* --beacon-url".into()),
    };

    /*
     * Perform the core "runs".
     */

    let mut block_root = None;
    for i in 0..runs {
        let start = Instant::now();

        block_root = Some(block.canonical_root());

        let duration = Instant::now().duration_since(start);
        info!("Run {}: {:?}", i, duration);
    }

    if let Some(block_root) = block_root {
        info!("Block root is {:?}", block_root);
    }

    Ok(())
}
