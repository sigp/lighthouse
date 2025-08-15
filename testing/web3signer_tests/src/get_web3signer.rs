//! This build script downloads the latest Web3Signer release and places it in the `OUT_DIR` so it
//! can be used for integration testing.

use reqwest::Client;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

/// Use `None` to download the latest Github release.
/// Use `Some("21.8.1")` to download a specific version.
const FIXED_VERSION_STRING: Option<&str> = None;

// This function no longer makes any attempt to avoid downloads, because in practice we use it
// with a fresh temp directory every time we run the tests. We might want to change this in future
// to enable reproducible/offline testing.
pub async fn download_binary(dest_dir: PathBuf) {
    let version = if let Some(version) = FIXED_VERSION_STRING {
        version.to_string()
    } else if let Ok(env_version) = env::var("LIGHTHOUSE_WEB3SIGNER_VERSION") {
        env_version
    } else {
        // The Consenys artifact server resolves `latest` to the latest release. We previously hit
        // the Github API to establish the version, but that is no longer necessary.
        "latest".to_string()
    };
    eprintln!("Downloading web3signer version: {version}");

    // Download the release zip.
    let client = Client::builder().build().unwrap();
    let zip_url = format!(
        "https://artifacts.consensys.net/public/web3signer/raw/names/web3signer.zip/versions/{}/web3signer-{}.zip",
        version, version
    );
    let zip_response = client
        .get(zip_url)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();

    // Write the zip to a file.
    let zip_path = dest_dir.join(format!("web3signer-{version}.zip"));
    fs::write(&zip_path, zip_response).unwrap();

    // Unzip the zip.
    let mut zip_file = fs::File::open(&zip_path).unwrap();
    ZipArchive::new(&mut zip_file)
        .unwrap()
        .extract(&dest_dir)
        .unwrap();

    // Rename the web3signer directory so it doesn't include the version string. This ensures the
    // path to the binary is predictable.
    let web3signer_dir = dest_dir.join("web3signer");
    if web3signer_dir.exists() {
        fs::remove_dir_all(&web3signer_dir).unwrap();
    }

    let versioned_web3signer_dir = find_versioned_web3signer_dir(&dest_dir);
    eprintln!(
        "Renaming versioned web3signer dir at: {}",
        versioned_web3signer_dir.display()
    );

    fs::rename(versioned_web3signer_dir, web3signer_dir).unwrap();

    // Delete zip.
    fs::remove_file(&zip_path).unwrap();
}

fn find_versioned_web3signer_dir(dest_dir: &Path) -> PathBuf {
    for entry in fs::read_dir(dest_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.starts_with("web3signer-"))
            .unwrap_or(false)
            && entry.file_type().unwrap().is_dir()
        {
            return path;
        }
    }
    panic!("no directory named web3signer-* found after ZIP extraction")
}
