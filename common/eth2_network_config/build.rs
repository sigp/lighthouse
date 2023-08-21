//! Extracts zipped genesis states on first run.
use eth2_config::{Eth2NetArchiveAndDirectory, ETH2_NET_DIRS, GENESIS_FILE_NAME, GENESIS_COMPRESSED_FILE_NAME};
use reqwest;
use std::fs::{File};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use tokio::runtime;
use tokio::task;
use tokio_stream::StreamExt;

fn main() {
    for network in ETH2_NET_DIRS {
        match uncompress_state(network) {
            Ok(()) => (),
            Err(e) => panic!(
                "Failed to uncompress {} genesis state file: {}",
                network.name, e
            ),
        }
    }
}

/// Uncompress the network configs archive into a network configs folder.
fn uncompress_state(network: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
    let genesis_ssz_path = network.dir().join(GENESIS_FILE_NAME);
    let genesis_compressed_ssz_path = network.dir().join(GENESIS_COMPRESSED_FILE_NAME);
    // Take care to not overwrite the genesis.ssz if it already exists, as that causes
    // spurious rebuilds.
    if genesis_ssz_path.exists() {
        return Ok(());
    }

    if network.genesis_is_known {
        // fetch snappy compressed genesis from remote url 
        let rt =
            runtime::Runtime::new().map_err(|e| format!("Error with blocking tasks: {}", e))?;

        let temp_file = rt.block_on(fetch_genesis_state_wrapper(
            network.remote_url,
            PathBuf::from(genesis_compressed_ssz_path),
        ))?;

        snappy_decode_genesis_file(temp_file, genesis_ssz_path)?;
    } else {
        // Create empty genesis.ssz if genesis is unknown
        File::create(genesis_ssz_path)
            .map_err(|e| format!("Failed to create {}: {}", GENESIS_FILE_NAME, e))?;
    }

    Ok(())
}

async fn fetch_compressed_genesis_state(url: &str, save_path: PathBuf) -> Result<File, String> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("Error fetching file from remote url: {}", e))?;

    // Ensure the request was successful
    if response.status().is_success() {
        // Open a file to write the content
        let mut dest = File::create(save_path)
            .map_err(|e| format!("Error creating file from remote url: {}", e))?;
        let mut content_stream = response.bytes_stream();

        // Write content stream to file
        while let Some(chunk) = content_stream.next().await {
            let buf = chunk.map_err(|e| format!("Error creating buffer: {}", e))?;
            dest.write_all(&buf)
                .map_err(|e| format!("Error writing buffer: {}", e))?;
        }

        return Ok(dest);
    }
    Err("Could not find file from remote url".to_string())
}

async fn fetch_genesis_state_wrapper(
    url: &'static str,
    save_path: PathBuf,
) -> Result<File, String> {
    let join_handle = task::spawn_blocking(|| {
        let inner_runtime = runtime::Runtime::new().unwrap();
        inner_runtime.block_on(fetch_compressed_genesis_state(url, save_path))
    });

    let result = join_handle
        .await
        .map_err(|e| format!("join handle error: {}", e))??;

    Ok(result)
}

fn snappy_decode_genesis_file(source_file: File, target_filename: PathBuf) -> Result<File, String> {
    let reader = BufReader::new(source_file);

    let mut decoder = snap::read::FrameDecoder::new(reader);

    let mut buffer = Vec::new();
    decoder
        .read_to_end(&mut buffer)
        .map_err(|e| format!("failed to decode: {}", e))?;

    let mut output_file = File::create(target_filename).unwrap();
    output_file
        .write_all(&buffer)
        .map_err(|e| format!("Error writing buffer: {}", e))?;

    Ok(output_file)
}
