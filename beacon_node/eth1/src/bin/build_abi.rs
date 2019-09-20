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

fn main() {
    match init_deposit_contract_abi() {
        Ok(()) => (),
        Err(e) => panic!(e),
    }
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn init_deposit_contract_abi() -> Result<(), String> {
    let local_file = abi_dir().join(format!("{}_{}", SPEC_TAG, ABI_FILE));

    if local_file.exists() {
        // Nothing to do.
    } else {
        match download_abi() {
            Ok(mut response) => {
                let mut file = File::create(local_file)
                    .map_err(|e| format!("Failed to create local abi file: {:?}", e))?;

                let contract: Value = response
                    .json()
                    .map_err(|e| format!("Respsonse is not a valid json {:?}", e))?;
                let abi = contract
                    .get("abi")
                    .ok_or(format!("Response does not contain key: abi"))?
                    .to_string();
                file.write(abi.as_bytes())
                    .map_err(|e| format!("Failed to write http response to file: {:?}", e))?;
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
        .join("abi");

    std::fs::create_dir_all(base.clone())
        .expect("should be able to create abi directory in manifest");

    base
}
