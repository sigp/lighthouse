//! Downloads the ABI and bytecode for the deposit contract from the ethereum spec repository and
//! stores them in a `contract/` directory in the crate root.
//!
//! These files are required for some `include_bytes` calls used in this crate.

use reqwest::Response;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const GITHUB_RAW: &str = "https://raw.githubusercontent.com";
const SPEC_REPO: &str = "ethereum/eth2.0-specs";
const SPEC_TAG: &str = "v0.8.3";
const ABI_FILE: &str = "validator_registration.json";
const BYTECODE_FILE: &str = "validator_registration.bytecode";

fn main() {
    match init_deposit_contract_abi() {
        Ok(()) => (),
        Err(e) => panic!(e),
    }
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn init_deposit_contract_abi() -> Result<(), String> {
    let abi_file = abi_dir().join(format!("{}_{}", SPEC_TAG, ABI_FILE));
    let bytecode_file = abi_dir().join(format!("{}_{}", SPEC_TAG, BYTECODE_FILE));

    if abi_file.exists() {
        // Nothing to do.
    } else {
        match download_abi() {
            Ok(mut response) => {
                let mut abi_file = File::create(abi_file)
                    .map_err(|e| format!("Failed to create local abi file: {:?}", e))?;
                let mut bytecode_file = File::create(bytecode_file)
                    .map_err(|e| format!("Failed to create local bytecode file: {:?}", e))?;

                let contract: Value = response
                    .json()
                    .map_err(|e| format!("Respsonse is not a valid json {:?}", e))?;

                let abi = contract
                    .get("abi")
                    .ok_or(format!("Response does not contain key: abi"))?
                    .to_string();
                abi_file
                    .write(abi.as_bytes())
                    .map_err(|e| format!("Failed to write http response to abi file: {:?}", e))?;

                let bytecode = contract
                    .get("bytecode")
                    .ok_or(format!("Response does not contain key: bytecode"))?
                    .to_string();
                bytecode_file.write(bytecode.as_bytes()).map_err(|e| {
                    format!("Failed to write http response to bytecode file: {:?}", e)
                })?;
            }
            Err(e) => {
                return Err(format!(
                    "No abi file found. Failed to download from github: {:?}",
                    e
                ))
            }
        }
    }

    Ok(())
}

/// Attempts to download the deposit contract file from the Ethereum github.
fn download_abi() -> Result<Response, String> {
    reqwest::get(&format!(
        "{}/{}/{}/deposit_contract/contracts/{}",
        GITHUB_RAW, SPEC_REPO, SPEC_TAG, ABI_FILE
    ))
    .map_err(|e| format!("Failed to download deposit ABI from github: {:?}", e))
}

/// Returns the directory that will be used to store the deposit contract ABI.
fn abi_dir() -> PathBuf {
    let base = env::var("CARGO_MANIFEST_DIR")
        .expect("should know manifest dir")
        .parse::<PathBuf>()
        .expect("should parse manifest dir as path")
        .join("contract");

    std::fs::create_dir_all(base.clone())
        .expect("should be able to create abi directory in manifest");

    base
}
