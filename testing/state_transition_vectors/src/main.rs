#[macro_use]
mod macros;
mod exit;

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use lazy_static::lazy_static;
use ssz::Encode;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use types::{
    test_utils::generate_deterministic_keypairs, BeaconState, EthSpec, Keypair, SignedBeaconBlock,
};
use types::{Hash256, MainnetEthSpec, Slot};

type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 64;

/// The base output directory for test vectors.
pub const BASE_VECTOR_DIR: &str = "vectors";

pub const SLOT_OFFSET: u64 = 1;

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

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness<E: EthSpec>(
    slot: Slot,
    validator_count: usize,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .build();
    let skip_to_slot = slot - SLOT_OFFSET;
    if skip_to_slot > Slot::new(0) {
        let state = harness.get_current_state();
        harness.add_attested_blocks_at_slots(
            state,
            Hash256::zero(),
            (skip_to_slot.as_u64()..slot.as_u64())
                .map(Slot::new)
                .collect::<Vec<_>>()
                .as_slice(),
            (0..validator_count).collect::<Vec<_>>().as_slice(),
        );
    }

    harness
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
fn write_to_ssz_file<T: Encode>(path: &Path, item: &T) -> Result<(), String> {
    write_to_file(path, &item.as_ssz_bytes())
}

/// Write some bytes to file.
fn write_to_file(path: &Path, item: &[u8]) -> Result<(), String> {
    File::create(path)
        .map_err(|e| format!("Unable to create {:?}: {:?}", path, e))
        .and_then(|mut file| {
            file.write_all(item)
                .map(|_| ())
                .map_err(|e| format!("Unable to write to {:?}: {:?}", path, e))
        })
}
