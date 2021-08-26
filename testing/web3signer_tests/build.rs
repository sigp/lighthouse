use reqwest::Client;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use tokio;
use zip::ZipArchive;

#[tokio::main]
async fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    download_binary(out_dir.into()).await;
}

pub async fn download_binary(dest_dir: PathBuf) {
    let version_file = dest_dir.join("version");

    let client = Client::builder()
        // Github gives a 403 without a user agent.
        .user_agent("web3signer_tests")
        .build()
        .unwrap();

    // Get the latest release of the web3 signer repo.
    let latest_response: Value = client
        .get("https://api.github.com/repos/ConsenSys/web3signer/releases/latest")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let latest_version = latest_response.get("tag_name").unwrap().as_str().unwrap();

    // If the latest version is already downloaded, do nothing.
    if version_file.exists() && fs::read(&version_file).unwrap() == latest_version.as_bytes() {
        return;
    } else {
        fs::remove_file(&version_file).unwrap();
    }

    // Download the latest release zip.
    let zip_url = format!("https://artifacts.consensys.net/public/web3signer/raw/names/web3signer.zip/versions/{}/web3signer-{}.zip", latest_version, latest_version);
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
    let zip_path = dest_dir.join(format!("{}.zip", latest_version));
    fs::write(&zip_path, zip_response).unwrap();
    // Extract the zip from the file.
    let mut zip_file = fs::File::open(&zip_path).unwrap();
    ZipArchive::new(&mut zip_file)
        .unwrap()
        .extract(&dest_dir)
        .unwrap();

    let unzipped_dir = dest_dir.join(format!("web3signer-{}", latest_version));
    let dst_binary_path = dest_dir.join("web3signer");
    let src_binary_path = unzipped_dir.join("bin").join("web3signer");

    // Copy the binary out of the unzipped dir.
    fs::remove_file(&dst_binary_path).unwrap();
    fs::copy(&src_binary_path, &dst_binary_path).unwrap();

    // Clean up zip and unzipped dir.
    fs::remove_dir_all(unzipped_dir).unwrap();
    fs::remove_file(&zip_path).unwrap();

    // Update the version file to avoid duplicate downloads.
    fs::write(&version_file, latest_version).unwrap();
}
