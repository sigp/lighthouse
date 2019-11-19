mod common;
mod eth1_genesis_service;
mod interop;

pub use eth1::Config as Eth1Config;
pub use eth1_genesis_service::Eth1GenesisService;
pub use interop::{interop_genesis_state, recent_genesis_time};
pub use types::test_utils::generate_deterministic_keypairs;

use ssz::Decode;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use types::{BeaconState, EthSpec};

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
