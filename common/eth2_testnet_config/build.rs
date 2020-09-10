//! Downloads a testnet configuration from Github.

use eth2_config::{altona, medalla, Eth2NetArchiveAndDirectory};
use handlebars::Handlebars;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use zip::ZipArchive;

const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] =
    &[altona::ETH2_NET_DIR, medalla::ETH2_NET_DIR];

fn main() {
    for testnet in ETH2_NET_DIRS {
        let testnet_dir = testnet.dir();
        let archive_fullpath = testnet.archive_fullpath();
        println!("archive fullpath: {:?}", archive_fullpath);

        if !testnet_dir.exists() && archive_fullpath.exists() {
            //uncompress archive and continue
            let archive_file = File::open(&archive_fullpath).unwrap();
            uncompress(archive_file);
        }
    }
}

fn uncompress(archive_file: File) {
    let mut archive = ZipArchive::new(archive_file).unwrap();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = file.sanitized_name();

        if (file.name().ends_with('/')) {
            fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p).unwrap();
                }
            }

            let mut outfile = File::create(&outpath).unwrap();
            io::copy(&mut file, &mut outfile).unwrap();
        }
    }
}

fn get_all_files(testnet: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
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

fn get_file(testnet: &Eth2NetArchiveAndDirectory, filename: &str) -> Result<(), String> {
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
