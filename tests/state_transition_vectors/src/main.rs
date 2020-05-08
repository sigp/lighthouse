#[macro_use]
mod macros;
mod exit;

use ssz::Encode;
use state_processing::test_utils::BlockProcessingBuilder;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;
use types::MainnetEthSpec;
use types::{BeaconState, ChainSpec, EthSpec, SignedBeaconBlock};

type E = MainnetEthSpec;

pub const NUM_DEPOSITS: u64 = 1;

pub const VALIDATOR_COUNT: usize = 64;
pub const EPOCH_OFFSET: u64 = 4;
pub const NUM_ATTESTATIONS: u64 = 1;

/// The base output directory for test vectors.
pub const BASE_VECTOR_DIR: &str = "vectors";

/// Writes all known test vectors to `CARGO_MANIFEST_DIR/vectors`.
fn main() {
    match write_all_vectors() {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            exit(1)
        }
    }
}

/// An abstract definition of a test vector that can be run as a test or exported to disk.
pub struct TestVector {
    pub title: String,
    pub pre_state: BeaconState<E>,
    pub block: SignedBeaconBlock<E>,
    pub post_state: Option<BeaconState<E>>,
    pub error: Option<String>,
}

/// Gets a `BlockProcessingBuilder` to be used in testing.
fn get_builder(
    spec: &ChainSpec,
    epoch_offset: u64,
    num_validators: usize,
) -> BlockProcessingBuilder<MainnetEthSpec> {
    // Set the state and block to be in the last slot of the `epoch_offset`th epoch.
    let last_slot_of_epoch = (MainnetEthSpec::genesis_epoch() + epoch_offset)
        .end_slot(MainnetEthSpec::slots_per_epoch());
    BlockProcessingBuilder::new(num_validators, last_slot_of_epoch, &spec).build_caches()
}

/// Writes all vectors to file.
fn write_all_vectors() -> Result<(), String> {
    write_vectors_to_file("exit", &exit::vectors())
}

/// Writes a list of `vectors` to the `title` dir.
fn write_vectors_to_file(title: &str, vectors: &[TestVector]) -> Result<(), String> {
    let dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| format!("Unable to find manifest dir: {:?}", e))?
        .parse::<PathBuf>()
        .map_err(|e| format!("Unable to parse manifest dir: {:?}", e))?
        .join(BASE_VECTOR_DIR)
        .join(title);

    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("Unable to remove {:?}: {:?}", dir, e))?;
    }
    fs::create_dir_all(&dir).map_err(|e| format!("Unable to create {:?}: {:?}", dir, e))?;

    for vector in vectors {
        let dir = dir.clone().join(&vector.title);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| format!("Unable to remove {:?}: {:?}", dir, e))?;
        }
        fs::create_dir_all(&dir).map_err(|e| format!("Unable to create {:?}: {:?}", dir, e))?;

        write_to_ssz_file(&dir.clone().join("pre.ssz"), &vector.pre_state)?;
        write_to_ssz_file(&dir.clone().join("block.ssz"), &vector.block)?;
        if let Some(post_state) = vector.post_state.as_ref() {
            write_to_ssz_file(&dir.clone().join("post.ssz"), post_state)?;
        }
        if let Some(error) = vector.error.as_ref() {
            write_to_file(&dir.clone().join("error.txt"), error.as_bytes())?;
        }
    }

    Ok(())
}

/// Write some SSZ object to file.
fn write_to_ssz_file<T: Encode>(path: &PathBuf, item: &T) -> Result<(), String> {
    write_to_file(path, &item.as_ssz_bytes())
}

/// Write some bytes to file.
fn write_to_file(path: &PathBuf, item: &[u8]) -> Result<(), String> {
    File::create(path)
        .map_err(|e| format!("Unable to create {:?}: {:?}", path, e))
        .and_then(|mut file| {
            file.write_all(item)
                .map(|_| ())
                .map_err(|e| format!("Unable to write to {:?}: {:?}", path, e))
        })
}
