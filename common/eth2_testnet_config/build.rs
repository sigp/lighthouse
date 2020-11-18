//! Downloads a testnet configuration from Github.

use eth2_config::{
    altona, mainnet, medalla, pyrmont, spadina, toledo, Eth2NetArchiveAndDirectory,
    GENESIS_FILE_NAME,
};
use std::fs::File;
use std::io;
use zip::ZipArchive;

const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] = &[
    altona::ETH2_NET_DIR,
    medalla::ETH2_NET_DIR,
    spadina::ETH2_NET_DIR,
    mainnet::ETH2_NET_DIR,
    pyrmont::ETH2_NET_DIR,
    toledo::ETH2_NET_DIR,
];

fn main() {
    for testnet in ETH2_NET_DIRS {
        match uncompress_state(testnet) {
            Ok(()) => (),
            Err(e) => panic!(
                "Failed to uncompress {} genesis state zip file: {}",
                testnet.name, e
            ),
        }
    }
}

/// Uncompress the testnet configs archive into a testnet configs folder.
fn uncompress_state(testnet: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
    if testnet.genesis_is_known {
        let archive_path = testnet.genesis_state_archive();
        let archive_file = File::open(&archive_path)
            .map_err(|e| format!("Failed to open archive file {:?}: {:?}", archive_path, e))?;

        let mut archive =
            ZipArchive::new(archive_file).map_err(|e| format!("Error with zip file: {}", e))?;

        let mut file = archive.by_name(GENESIS_FILE_NAME).map_err(|e| {
            format!(
                "Error retrieving file {} inside zip: {}",
                GENESIS_FILE_NAME, e
            )
        })?;
        let path = testnet.dir().join(GENESIS_FILE_NAME);
        let mut outfile = File::create(&path)
            .map_err(|e| format!("Error while creating file {:?}: {}", path, e))?;
        io::copy(&mut file, &mut outfile)
            .map_err(|e| format!("Error writing file {:?}: {}", path, e))?;
    } else {
        // Create empty genesis.ssz if genesis is unknown
        File::create(testnet.dir().join(GENESIS_FILE_NAME))
            .map_err(|e| format!("Failed to create {}: {}", GENESIS_FILE_NAME, e))?;
    }

    Ok(())
}
