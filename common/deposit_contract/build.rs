//! Downloads the ABI and bytecode for the deposit contract from the ethereum spec repository and
//! stores them in a `contract/` directory in the crate root.
//!
//! These files are required for some `include_bytes` calls used in this crate.

use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const TAG: &str = "v0.12.1";
// NOTE: the version of the unsafe contract lags the main tag, but the v0.9.2.1 code is compatible
// with the unmodified v0.12.1 contract
const UNSAFE_TAG: &str = "v0.9.2.1";

// Checksums for the production smart contract.
const ABI_CHECKSUM: &str = "e53a64aecdd14f7c46c4134d19500c3184bf083b046347fb14c7828a26f2bff6";
const BYTECODE_CHECKSUM: &str = "ace004b44a9f531bcd47f9d8827b2527c713a2df3af943ac28ecc3df2aa355d6";

// Checksums for the testnet smart contract.
const TESTNET_ABI_CHECKSUM: &str =
    "c9a0a6b3fd48b94193d48c48abad3edcd61eb645d8cdfc9d969d188beb34f5c1";
const TESTNET_BYTECODE_CHECKSUM: &str =
    "2b054e7d134e2d66566ba074c8a18a3a67841d67c8ef6175fc95f1639ee73a89";

fn spec_url() -> String {
    env::var("LIGHTHOUSE_DEPOSIT_CONTRACT_SPEC_URL")
    .unwrap_or(format!("https://raw.githubusercontent.com/ethereum/eth2.0-specs/{}/deposit_contract/contracts/validator_registration.json", TAG))
}
fn testnet_url() -> String {
    env::var("LIGHTHOUSE_DEPOSIT_CONTRACT_TESTNET_URL")
    .unwrap_or(format!("https://raw.githubusercontent.com/sigp/unsafe-eth2-deposit-contract/{}/unsafe_validator_registration.json", UNSAFE_TAG))
}

fn read_contract_file_from_url(url: Url) -> Result<Value, String> {
    if url.scheme() == "file" {
        let path = url
            .to_file_path()
            .map_err(|e| format!("Unable to get file path from url: {:?}", e))?;

        let file = File::open(path).map_err(|e| format!("Unable to open json file: {:?}", e))?;

        let contract: Value = serde_json::from_reader(file)
            .map_err(|e| format!("Unable to read from jeson file: {:?}", e))?;
        Ok(contract)
    } else {
        match reqwest::blocking::get(url) {
            Ok(response) => {
                let contract: Value = response
                    .json()
                    .map_err(|e| format!("Respsonse is not a valid json {:?}", e))?;
                Ok(contract)
            }
            Err(e) => {
                return Err(format!(
                    "No abi file found. Failed to download from github: {:?}",
                    e
                ))
            }
        }
    }
}

fn main() {
    match get_all_contracts() {
        Ok(()) => (),
        Err(e) => panic!("{}", e),
    }
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn get_all_contracts() -> Result<(), String> {
    download_deposit_contract(
        &spec_url(),
        "validator_registration.json",
        ABI_CHECKSUM,
        "validator_registration.bytecode",
        BYTECODE_CHECKSUM,
    )?;
    download_deposit_contract(
        &testnet_url(),
        "testnet_validator_registration.json",
        TESTNET_ABI_CHECKSUM,
        "testnet_validator_registration.bytecode",
        TESTNET_BYTECODE_CHECKSUM,
    )
}

/// Attempts to download the deposit contract ABI from github if a local copy is not already
/// present.
pub fn download_deposit_contract(
    url: &str,
    abi_file: &str,
    abi_checksum: &str,
    bytecode_file: &str,
    bytecode_checksum: &str,
) -> Result<(), String> {
    let abi_file = abi_dir().join(format!("{}_{}", TAG, abi_file));
    let bytecode_file = abi_dir().join(format!("{}_{}", TAG, bytecode_file));
    let url = reqwest::Url::parse(url).map_err(|e| format!("Unable to parse url: {}", e))?;

    if abi_file.exists() {
        // Nothing to do.
    } else {
        let contract = read_contract_file_from_url(url)?;

        let mut abi_file = File::create(abi_file)
            .map_err(|e| format!("Failed to create local abi file: {:?}", e))?;
        let mut bytecode_file = File::create(bytecode_file)
            .map_err(|e| format!("Failed to create local bytecode file: {:?}", e))?;

        let abi = contract
            .get("abi")
            .ok_or("Response does not contain key: abi")?
            .to_string();

        verify_checksum(abi.as_bytes(), abi_checksum);

        abi_file
            .write(abi.as_bytes())
            .map_err(|e| format!("Failed to write http response to abi file: {:?}", e))?;

        let bytecode = contract
            .get("bytecode")
            .ok_or("Response does not contain key: bytecode")?
            .to_string();

        verify_checksum(bytecode.as_bytes(), bytecode_checksum);

        bytecode_file
            .write(bytecode.as_bytes())
            .map_err(|e| format!("Failed to write http response to bytecode file: {:?}", e))?;
    }

    Ok(())
}

fn verify_checksum(bytes: &[u8], expected_checksum: &str) {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();

    let checksum = hex::encode(&result[..]);

    assert_eq!(
        &checksum, expected_checksum,
        "Checksum {} did not match {}",
        checksum, expected_checksum
    );
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
