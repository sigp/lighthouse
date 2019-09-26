use clap::ArgMatches;
use ssz::Decode;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use types::{BeaconState, EthSpec};

pub fn run_pycli<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let cmd_path = matches
        .value_of("pycli-path")
        .ok_or_else(|| "No pycli-path supplied")?;

    let pycli = PyCli::new(cmd_path.to_string())?;

    let block_path = PathBuf::from("/tmp/trinity/block_16.ssz");
    let pre_state_path = PathBuf::from("/tmp/trinity/state_15.ssz");

    pycli
        .transition_blocks::<T>(block_path, pre_state_path)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// A wrapper around Danny Ryan's `pycli` utility:
///
/// https://github.com/djrtwo/pycli
///
/// Provides functions for testing consensus logic against the executable Python spec.
pub struct PyCli {
    cmd_path: PathBuf,
}

impl PyCli {
    /// Create a new instance, parsing the given `cmd_path` as a canonical path.
    pub fn new(cmd_path: String) -> Result<Self, String> {
        Ok(Self {
            cmd_path: fs::canonicalize(cmd_path)
                .map_err(|e| format!("Failed to canonicalize pycli path: {:?}", e))?,
        })
    }

    /// Performs block processing on the state at the given `pre_state_path`, using the block at
    /// `block_path`.
    ///
    /// Returns an SSZ-encoded `BeaconState` on success.
    pub fn transition_blocks<T: EthSpec>(
        &self,
        block_path: PathBuf,
        pre_state_path: PathBuf,
    ) -> Result<BeaconState<T>, String> {
        let output = Command::new("python")
            .current_dir(self.cmd_path.clone())
            .arg("pycli.py")
            .arg("transition")
            .arg("blocks")
            .arg(format!("--pre={}", path_string(pre_state_path)?))
            .arg(path_string(block_path)?)
            .output()
            .map_err(|e| format!("Failed to run command: {:?}", e))?;

        if output.status.success() {
            let state = BeaconState::from_ssz_bytes(&output.stdout)
                .map_err(|e| format!("Failed to parse SSZ: {:?}", e))?;
            Ok(state)
        } else {
            Err(format!("pycli returned an error: {:?}", output))
        }
    }
}

fn path_string(path: PathBuf) -> Result<String, String> {
    let path =
        fs::canonicalize(path).map_err(|e| format!("Unable to canonicalize path: {:?}", e))?;

    path.into_os_string()
        .into_string()
        .map_err(|p| format!("Unable to stringify path: {:?}", p))
}
