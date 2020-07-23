//! Downloads a testnet configuration from Github.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const TESTNET_ID: &str = "altona-v3";

fn main() {
    if !base_dir().exists() {
        std::fs::create_dir_all(base_dir())
            .unwrap_or_else(|_| panic!("Unable to create {:?}", base_dir()));

        match get_all_files() {
            Ok(()) => (),
            Err(e) => {
                std::fs::remove_dir_all(base_dir()).unwrap_or_else(|_| panic!(
                    "{}. Failed to remove {:?}, please remove the directory manually because it may contains incomplete testnet data.",
                    e,
                    base_dir(),
                ));
                panic!(e);
            }
        }
    }
}

pub fn get_all_files() -> Result<(), String> {
    get_file("boot_enr.yaml")?;
    get_file("config.yaml")?;
    get_file("deploy_block.txt")?;
    get_file("deposit_contract.txt")?;
    get_file("genesis.ssz")?;

    Ok(())
}

pub fn get_file(filename: &str) -> Result<(), String> {
    let url = format!(
        "https://raw.githubusercontent.com/sigp/witti/a94e00c1a03df851f960fcf44a79f2a6b1d29af1/altona/lighthouse/{}",
        filename
    );

    let path = base_dir().join(filename);
    let mut file =
        File::create(path).map_err(|e| format!("Failed to create {}: {:?}", filename, e))?;

    let request = reqwest::blocking::Client::builder()
        .build()
        .map_err(|_| "Could not build request client".to_string())?
        .get(&url)
        .timeout(std::time::Duration::from_secs(120));

    let contents = request
        .send()
        .map_err(|e| format!("Failed to download {}: {}", filename, e))?
        .error_for_status()
        .map_err(|e| format!("Error downloading {}: {}", filename, e))?
        .bytes()
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
