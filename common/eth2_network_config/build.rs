//! Extracts zipped genesis states on first run.
use eth2_config::{Eth2NetArchiveAndDirectory, ETH2_NET_DIRS, GENESIS_FILE_NAME};
use std::fs::File;
use std::io;
use zip::ZipArchive;

fn main() {
    for network in ETH2_NET_DIRS {
        match uncompress_state(network) {
            Ok(()) => (),
            Err(e) => panic!(
                "Failed to uncompress {} genesis state zip file: {}",
                network.name, e
            ),
        }
    }
}

/// Uncompress the network configs archive into a network configs folder.
fn uncompress_state(network: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
    let genesis_ssz_path = network.dir().join(GENESIS_FILE_NAME);

    // Take care to not overwrite the genesis.ssz if it already exists, as that causes
    // spurious rebuilds.
    if genesis_ssz_path.exists() {
        return Ok(());
    }

    if network.genesis_is_known {
        // Extract genesis state from genesis.ssz.zip
        let archive_path = network.genesis_state_archive();
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
        let mut outfile = File::create(&genesis_ssz_path)
            .map_err(|e| format!("Error while creating file {:?}: {}", genesis_ssz_path, e))?;
        io::copy(&mut file, &mut outfile)
            .map_err(|e| format!("Error writing file {:?}: {}", genesis_ssz_path, e))?;
    } else {
        // Create empty genesis.ssz if genesis is unknown
        File::create(genesis_ssz_path)
            .map_err(|e| format!("Failed to create {}: {}", GENESIS_FILE_NAME, e))?;
    }

    Ok(())
}
