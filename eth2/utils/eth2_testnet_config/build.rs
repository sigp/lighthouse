/// Pulls down the latest Lighthouse testnet from https://github.com/eth2-clients/eth2-testnets
use reqwest;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const TESTNET_ID: &str = "testnet5";

fn main() {
    match get_all_files() {
        Ok(()) => (),
        Err(e) => panic!(e),
    }
}

pub fn get_all_files() -> Result<(), String> {
    if !base_dir().exists() {
        std::fs::create_dir_all(base_dir())
            .map_err(|e| format!("Unable to create {:?}: {}", base_dir(), e))?;

        get_file("boot_enr.yaml")?;
        get_file("config.yaml")?;
        get_file("deploy_block.txt")?;
        get_file("deposit_contract.txt")?;
        get_file("genesis.ssz")?;
    }

    Ok(())
}

pub fn get_file(filename: &str) -> Result<(), String> {
    let url = format!(
        "https://raw.githubusercontent.com/eth2-clients/eth2-testnets/master/lighthouse/{}/{}",
        TESTNET_ID, filename
    );

    let path = base_dir().join(filename);
    let mut file =
        File::create(path).map_err(|e| format!("Failed to create {}: {:?}", filename, e))?;

    let mut response =
        reqwest::get(&url).map_err(|e| format!("Failed to download {}: {}", filename, e))?;
    let mut contents: Vec<u8> = vec![];
    response
        .copy_to(&mut contents)
        .map_err(|e| format!("Failed to read {} response bytes: {}", filename, e))?;

    file.write(&contents)
        .map_err(|e| format!("Failed to write to {}: {:?}", filename, e))?;

    Ok(())
}

fn base_dir() -> PathBuf {
    env::var("CARGO_MANIFEST_DIR")
        .expect("should know manifest dir")
        .parse::<PathBuf>()
        .expect("should parse manifest dir as path")
        .join(TESTNET_ID)
}
