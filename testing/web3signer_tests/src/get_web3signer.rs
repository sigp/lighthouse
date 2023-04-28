//! This build script downloads the latest Web3Signer release and places it in the `OUT_DIR` so it
//! can be used for integration testing.

use reqwest::{
    header::{self, HeaderValue},
    Client,
};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use zip::ZipArchive;

/// Use `None` to download the latest Github release.
/// Use `Some("21.8.1")` to download a specific version.
const FIXED_VERSION_STRING: Option<&str> = None;

pub async fn download_binary(dest_dir: PathBuf, github_token: &str) {
    let version_file = dest_dir.join("version");

    let client = Client::builder()
        // Github gives a 403 without a user agent.
        .user_agent("web3signer_tests")
        .build()
        .unwrap();

    let version = if let Some(version) = FIXED_VERSION_STRING {
        version.to_string()
    } else if let Ok(env_version) = env::var("LIGHTHOUSE_WEB3SIGNER_VERSION") {
        env_version
    } else {
        // Get the latest release of the web3 signer repo.
        let mut token_header_value = HeaderValue::from_str(github_token).unwrap();
        token_header_value.set_sensitive(true);
        let latest_response: Value = client
            .get("https://api.github.com/repos/ConsenSys/web3signer/releases/latest")
            .header(header::AUTHORIZATION, token_header_value)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        latest_response
            .get("tag_name")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    };

    if version_file.exists() && fs::read(&version_file).unwrap() == version.as_bytes() {
        // The latest version is already downloaded, do nothing.
        return;
    } else {
        // Ignore the result since we don't care if the version file already exists.
        let _ = fs::remove_file(&version_file);
    }

    // Download the latest release zip.
    let zip_url = format!("https://artifacts.consensys.net/public/web3signer/raw/names/web3signer.zip/versions/{}/web3signer-{}.zip", version, version);
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
    let zip_path = dest_dir.join(format!("{}.zip", version));
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
    fs::rename(
        dest_dir.join(format!("web3signer-{}", version)),
        web3signer_dir,
    )
    .unwrap();

    // Delete zip and unzipped dir.
    fs::remove_file(&zip_path).unwrap();

    // Update the version file to avoid duplicate downloads.
    fs::write(&version_file, version).unwrap();
}
