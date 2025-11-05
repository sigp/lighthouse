use crate::build_utils;
use crate::execution_engine::GenericExecutionEngine;
use crate::genesis_json::geth_genesis_json;
use network_utils::unused_port::unused_tcp4_port;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::{env, fs};
use tempfile::TempDir;

const GETH_BRANCH: &str = "master";
const GETH_REPO_URL: &str = "https://github.com/ethereum/go-ethereum";

pub fn build_result(repo_dir: &Path) -> Output {
    Command::new("make")
        .arg("geth")
        .current_dir(repo_dir)
        // Geth now uses the commit hash from a GitHub runner environment variable if it detects a CI environment.
        // We need to override this to successfully build Geth in Lighthouse workflows.
        // See: https://github.com/ethereum/go-ethereum/blob/668c3a7278af399c0e776e92f1c721b5158388f2/internal/build/env.go#L95-L121
        .env("CI", "false")
        .output()
        .expect("failed to make geth")
}

pub fn build(execution_clients_dir: &Path) {
    let repo_dir = execution_clients_dir.join("go-ethereum");

    if !repo_dir.exists() {
        // Clone the repo
        build_utils::clone_repo(execution_clients_dir, GETH_REPO_URL).unwrap();
    }

    // Get the latest tag on the branch
    let last_release = build_utils::get_latest_release(&repo_dir, GETH_BRANCH).unwrap();
    build_utils::checkout(&repo_dir, dbg!(&last_release)).unwrap();

    // Build geth
    build_utils::check_command_output(build_result(&repo_dir), || {
        format!("geth make failed using release {last_release}")
    });
}

fn get_geth_latest_version() -> Result<(String, String), String> {
    let api_url = "https://api.github.com/repos/ethereum/go-ethereum/releases/latest";

    let output = Command::new("curl")
        .arg("-sL")
        .arg(api_url)
        .output()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to get GitHub API response: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    let tag_name = json["tag_name"]
        .as_str()
        .ok_or_else(|| "Missing tag_name in response".to_string())?;

    let version = tag_name.trim_start_matches('v');

    // Get the commit SHA for this tag
    let tag_api_url = format!(
        "https://api.github.com/repos/ethereum/go-ethereum/git/refs/tags/{}",
        tag_name
    );

    let tag_output = Command::new("curl")
        .arg("-sL")
        .arg(&tag_api_url)
        .output()
        .map_err(|e| format!("Failed to execute curl for tag info: {}", e))?;

    if !tag_output.status.success() {
        return Err(format!(
            "Failed to get tag info: {}",
            String::from_utf8_lossy(&tag_output.stderr)
        ));
    }

    let tag_json: Value = serde_json::from_slice(&tag_output.stdout)
        .map_err(|e| format!("Failed to parse tag JSON response: {}", e))?;

    let commit_sha = tag_json["object"]["sha"]
        .as_str()
        .ok_or_else(|| "Missing commit SHA in tag response".to_string())?;

    let short_hash = &commit_sha[..8.min(commit_sha.len())];

    Ok((version.to_string(), short_hash.to_string()))
}

fn try_download_binary(execution_clients_dir: &Path) -> Result<(), String> {
    let (os, arch) = build_utils::get_platform_arch()?;

    // Geth only provides pre-built binaries for Linux platforms
    if os != "linux" {
        return Err(format!(
            "Pre-built Geth binaries not available for {os}-{arch}",
        ));
    }

    let geth_binary = GethEngine::binary_path();
    let geth_dir = geth_binary.parent().unwrap();
    fs::create_dir_all(geth_dir).map_err(|e| format!("Failed to create directory: {}", e))?;

    println!("Downloading latest Geth binary for {}-{}", os, arch);

    let (version, short_hash) = get_geth_latest_version()?;

    // Construct gethstore URL: https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-{version}-{commit}.tar.gz
    let download_url = format!(
        "https://gethstore.blob.core.windows.net/builds/geth-{}-{}-{}-{}.tar.gz",
        os, arch, version, short_hash
    );

    let archive_path = execution_clients_dir.join(format!("geth-{}.tar.gz", version));
    build_utils::download_file(&download_url, &archive_path)?;

    let temp_extract_dir = execution_clients_dir.join("geth-temp");
    let _ = fs::remove_dir_all(&temp_extract_dir);
    fs::create_dir_all(&temp_extract_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;
    build_utils::extract_tar_gz(&archive_path, &temp_extract_dir)?;

    let extracted_dir = fs::read_dir(&temp_extract_dir)
        .map_err(|e| format!("Failed to read temp directory: {}", e))?
        .find_map(|entry| {
            let entry = entry.ok()?;
            if entry.file_type().ok()?.is_dir() {
                Some(entry.path())
            } else {
                None
            }
        })
        .ok_or_else(|| "Failed to find extracted Geth directory".to_string())?;

    let extracted_geth = extracted_dir.join("geth");
    if !extracted_geth.exists() {
        return Err(format!(
            "Geth binary not found in extracted archive at {}",
            extracted_geth.display()
        ));
    }

    fs::copy(&extracted_geth, &geth_binary)
        .map_err(|e| format!("Failed to copy geth binary: {}", e))?;
    build_utils::make_executable(&geth_binary)?;

    fs::remove_file(&archive_path).unwrap_or_default();
    fs::remove_dir_all(&temp_extract_dir).unwrap_or_default();

    println!("Geth downloaded and installed successfully");

    Ok(())
}

pub fn download_or_build(execution_clients_dir: &Path) {
    let geth_binary = GethEngine::binary_path();
    if geth_binary.exists() {
        println!("Geth binary already exists, skipping");
        return;
    }

    println!("Attempting to download Geth binary...");

    if let Err(e) = try_download_binary(execution_clients_dir) {
        println!("Failed to download Geth binary: {}", e);
        println!("Falling back to building from source...");

        // Clean up any partial download directories that might conflict with git clone
        let geth_dir = geth_binary.parent().unwrap();
        let _ = fs::remove_dir_all(geth_dir);

        build(execution_clients_dir);
    }
}

pub fn clean(execution_clients_dir: &Path) {
    let repo_dir = execution_clients_dir.join("go-ethereum");
    if let Err(e) = fs::remove_dir_all(repo_dir) {
        eprintln!("Error while deleting folder: {}", e);
    }
}

/*
 * Geth-specific Implementation for GenericExecutionEngine
 */

#[derive(Clone)]
pub struct GethEngine;

impl GethEngine {
    fn binary_path() -> PathBuf {
        let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
        manifest_dir
            .join("execution_clients")
            .join("go-ethereum")
            .join("build")
            .join("bin")
            .join("geth")
    }
}

impl GenericExecutionEngine for GethEngine {
    fn init_datadir() -> TempDir {
        let datadir = TempDir::new().unwrap();

        let genesis_json_path = datadir.path().join("genesis.json");
        let mut file = fs::File::create(&genesis_json_path).unwrap();
        let json = geth_genesis_json();
        serde_json::to_writer(&mut file, &json).unwrap();

        let output = Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("init")
            .arg(genesis_json_path.to_str().unwrap())
            .output()
            .expect("failed to init geth");

        build_utils::check_command_output(output, || "geth init failed".into());

        datadir
    }

    fn start_client(
        datadir: &TempDir,
        http_port: u16,
        http_auth_port: u16,
        jwt_secret_path: PathBuf,
    ) -> Child {
        let network_port = unused_tcp4_port().unwrap();

        Command::new(Self::binary_path())
            .arg("--datadir")
            .arg(datadir.path().to_str().unwrap())
            .arg("--http")
            .arg("--http.api")
            .arg("engine,eth")
            .arg("--http.port")
            .arg(http_port.to_string())
            .arg("--authrpc.port")
            .arg(http_auth_port.to_string())
            .arg("--port")
            .arg(network_port.to_string())
            .arg("--allow-insecure-unlock")
            .arg("--authrpc.jwtsecret")
            .arg(jwt_secret_path.as_path().to_str().unwrap())
            // This flag is required to help Geth perform reliably when feeding it blocks
            // one-by-one. For more information, see:
            //
            // https://github.com/sigp/lighthouse/pull/3382#issuecomment-1197680345
            .arg("--syncmode=full")
            .stdout(build_utils::build_stdio())
            .stderr(build_utils::build_stdio())
            .spawn()
            .expect("failed to start geth")
    }
}
