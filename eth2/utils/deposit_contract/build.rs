//! Downloads the ABI and bytecode for the deposit contract from the ethereum spec repository and
//! stores them in a `contract/` directory in the crate root.
//!
//! These files are required for some `include_bytes` calls used in this crate.

use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const TAG: &str = "v0.11.1";
// NOTE: the version of the unsafe contract lags the main tag, but the v0.9.2.1 code is compatible
// with the unmodified v0.11.1 contract
const UNSAFE_TAG: &str = "v0.9.2.1";

fn spec_url() -> String {
    format!("https://raw.githubusercontent.com/ethereum/eth2.0-specs/{}/deposit_contract/contracts/validator_registration.json", TAG)
}
fn testnet_url() -> String {
    format!("https://raw.githubusercontent.com/sigp/unsafe-eth2-deposit-contract/{}/unsafe_validator_registration.json", UNSAFE_TAG)
}

fn main() {
    match get_all_contracts() {
        Ok(()) => (),
        Err(e) => panic!(e),
    }
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn get_all_contracts() -> Result<(), String> {
    download_deposit_contract(
        &spec_url(),
        "validator_registration.json",
        "validator_registration.bytecode",
    )?;
    download_deposit_contract(
        &testnet_url(),
        "testnet_validator_registration.json",
        "testnet_validator_registration.bytecode",
    )
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn download_deposit_contract(
    url: &str,
    abi_file: &str,
    bytecode_file: &str,
) -> Result<(), String> {
    let abi_file = abi_dir().join(format!("{}_{}", TAG, abi_file));
    let bytecode_file = abi_dir().join(format!("{}_{}", TAG, bytecode_file));

    if abi_file.exists() {
        // Nothing to do.
    } else {
        match reqwest::get(url) {
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

/// Returns the directory that will be used to store the deposit contract ABI.
fn abi_dir() -> PathBuf {
    let base = env::var("CARGO_MANIFEST_DIR")
        .expect("should know manifest dir")
        .parse::<PathBuf>()
        .expect("should parse manifest dir as path")
        .join("contracts");

    std::fs::create_dir_all(base.clone())
        .expect("should be able to create abi directory in manifest");

    base
}
