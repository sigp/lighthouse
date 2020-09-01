//! Downloads a testnet configuration from Github.

use eth2_config::{altona, medalla, Eth2NetDirectory};
use handlebars::Handlebars;
use serde_json::json;
use std::fs::File;
use std::io::Write;

const ETH2_NET_DIRS: &[Eth2NetDirectory<'static>] = &[altona::ETH2_NET_DIR, medalla::ETH2_NET_DIR];

fn main() {
    for testnet in ETH2_NET_DIRS {
        let testnet_dir = testnet.dir();

        if !testnet_dir.exists() {
            std::fs::create_dir_all(&testnet_dir)
                .unwrap_or_else(|_| panic!("Unable to create {:?}", testnet_dir));

            match get_all_files(testnet) {
                Ok(()) => (),
                Err(e) => {
                    std::fs::remove_dir_all(&testnet_dir).unwrap_or_else(|_| panic!(
                        "{}. Failed to remove {:?}, please remove the directory manually because it may contains incomplete testnet data.",
                        e,
                        testnet_dir,
                    ));
                    panic!(e);
                }
            }
        }
    }
}

fn get_all_files(testnet: &Eth2NetDirectory<'static>) -> Result<(), String> {
    get_file(testnet, "boot_enr.yaml")?;
    get_file(testnet, "config.yaml")?;
    get_file(testnet, "deploy_block.txt")?;
    get_file(testnet, "deposit_contract.txt")?;

    if testnet.genesis_is_known {
        get_file(testnet, "genesis.ssz")?;
    } else {
        File::create(testnet.dir().join("genesis.ssz")).unwrap();
    }

    Ok(())
}

fn get_file(testnet: &Eth2NetDirectory, filename: &str) -> Result<(), String> {
    let url = Handlebars::new()
        .render_template(
            testnet.url_template,
            &json!({"commit": testnet.commit, "file": filename}),
        )
        .unwrap();

    let path = testnet.dir().join(filename);

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
