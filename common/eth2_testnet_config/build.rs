//! Downloads a testnet configuration from Github.

use eth2_config::{altona, medalla, Eth2NetArchiveAndDirectory};
use std::fs;
use std::fs::File;
use std::io;
use zip::ZipArchive;

const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] =
    &[altona::ETH2_NET_DIR, medalla::ETH2_NET_DIR];

fn main() {
    for testnet in ETH2_NET_DIRS {
        let testnet_dir = testnet.dir();
        let archive_fullpath = testnet.archive_fullpath();
        //no need to do anything if archives have already been uncompressed before
        if !testnet_dir.exists() {
            if archive_fullpath.exists() {
                //uncompress archive and continue
                let archive_file = match File::open(&archive_fullpath) {
                    Ok(f) => f,
                    Err(e) => panic!("Problem opening archive file: {}", e),
                };

                match uncompress(archive_file) {
                    Ok(_) => (),
                    Err(e) => panic!(e),
                };
            } else {
                panic!(
                    "Couldn't find testnet archive at this location: {:?}",
                    archive_fullpath
                );
            }
        }
    }
}

fn uncompress(archive_file: File) -> Result<(), String> {
    let mut archive =
        ZipArchive::new(archive_file).map_err(|e| format!("Error with zip file: {}", e))?;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| format!("Error retrieving file {} inside zip: {}", i, e))?;

        let outpath = file.sanitized_name();

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)
                .map_err(|e| format!("Error creating testnet directories: {}", e))?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)
                        .map_err(|e| format!("Error creating testnet directories: {}", e))?;
                }
            }

            let mut outfile = File::create(&outpath)
                .map_err(|e| format!("Error while creating file {:?}: {}", outpath, e))?;
            io::copy(&mut file, &mut outfile)
                .map_err(|e| format!("Error writing file {:?}: {}", outpath, e))?;
        }
    }

    Ok(())
}
