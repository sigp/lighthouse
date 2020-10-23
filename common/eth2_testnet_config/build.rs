//! Downloads a testnet configuration from Github.

use eth2_config::{altona, medalla, spadina, zinken, Eth2NetArchiveAndDirectory};
use std::fs;
use std::fs::File;
use std::io;
use zip::ZipArchive;

const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] = &[
    altona::ETH2_NET_DIR,
    medalla::ETH2_NET_DIR,
    spadina::ETH2_NET_DIR,
    zinken::ETH2_NET_DIR,
];

fn main() {
    for testnet in ETH2_NET_DIRS {
        match uncompress(testnet) {
            Ok(()) => (),
            Err(e) => panic!("Failed to uncompress testnet zip file: {}", e),
        }
    }
}

/// Uncompress the testnet configs archive into a testnet configs folder.
fn uncompress(testnet: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
    let archive_file = File::open(&testnet.archive_fullpath())
        .map_err(|e| format!("Failed to open archive file: {:?}", e))?;

    let mut archive =
        ZipArchive::new(archive_file).map_err(|e| format!("Error with zip file: {}", e))?;

    // Create testnet dir
    fs::create_dir_all(testnet.dir())
        .map_err(|e| format!("Failed to create testnet directory: {:?}", e))?;

    // Create empty genesis.ssz if genesis is unknown
    if !testnet.genesis_is_known {
        File::create(testnet.dir().join("genesis.ssz"))
            .map_err(|e| format!("Failed to create genesis.ssz: {}", e))?;
    }

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Error retrieving file {} inside zip: {}", i, e))?;

        let path = testnet.dir().join(file.name());

        let mut outfile = File::create(&path)
            .map_err(|e| format!("Error while creating file {:?}: {}", path, e))?;
        io::copy(&mut file, &mut outfile)
            .map_err(|e| format!("Error writing file {:?}: {}", path, e))?;
    }

    Ok(())
}
