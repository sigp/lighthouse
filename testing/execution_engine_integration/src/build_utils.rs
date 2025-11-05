use crate::SUPPRESS_LOGS;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub fn get_platform_arch() -> Result<(&'static str, &'static str), String> {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    match (os, arch) {
        ("linux", "x86_64") => Ok(("linux", "amd64")),
        ("linux", "aarch64") => Ok(("linux", "arm64")),
        _ => Err(format!("Unsupported platform: {}-{}", os, arch)),
    }
}

pub fn prepare_dir() -> PathBuf {
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let execution_clients_dir = manifest_dir.join("execution_clients");

    if !execution_clients_dir.exists() {
        fs::create_dir(&execution_clients_dir).unwrap();
    }

    execution_clients_dir
}

pub fn clone_repo(repo_dir: &Path, repo_url: &str) -> Result<(), String> {
    output_to_result(
        Command::new("git")
            .arg("clone")
            .arg(repo_url)
            .current_dir(repo_dir)
            .output()
            .map_err(|_| format!("failed to clone repo at {repo_url}"))?,
        |_| {},
    )
}

pub fn checkout(repo_dir: &Path, revision_or_branch: &str) -> Result<(), String> {
    output_to_result(
        Command::new("git")
            .arg("checkout")
            .arg(revision_or_branch)
            .current_dir(repo_dir)
            .output()
            .map_err(|_| {
                format!(
                    "failed to checkout branch or revision at {repo_dir:?}/{revision_or_branch}",
                )
            })?,
        |_| {},
    )?;
    output_to_result(
        Command::new("git")
            .arg("submodule")
            .arg("update")
            .arg("--init")
            .arg("--recursive")
            .current_dir(repo_dir)
            .output()
            .map_err(|_| {
                format!(
                    "failed to update submodules on branch or revision at {repo_dir:?}/{revision_or_branch}",
                )
            })?,
        |_| {},
    )
}

/// Gets the last annotated tag of the given repo.
pub fn get_latest_release(repo_dir: &Path, branch_name: &str) -> Result<String, String> {
    // If the directory was already present it is possible we don't have the most recent tags.
    // Fetch them
    output_to_result(
        Command::new("git")
            .arg("fetch")
            .arg("--tags")
            .arg("--force")
            .current_dir(repo_dir)
            .output()
            .map_err(|e| format!("Failed to fetch tags for {repo_dir:?}: Err: {e}"))?,
        |_| {},
    )?;
    output_to_result(
        Command::new("git")
            .arg("describe")
            .arg(format!("origin/{branch_name}"))
            .arg("--abbrev=0")
            .arg("--tags")
            .current_dir(repo_dir)
            .output()
            .map_err(|e| format!("Failed to get latest tag for {repo_dir:?}: Err: {e}"))?,
        |stdout| {
            let tag = String::from_utf8_lossy(&stdout);
            tag.trim().to_string()
        },
    )
}

#[allow(dead_code)]
pub fn update_branch(repo_dir: &Path, branch_name: &str) -> Result<(), String> {
    output_to_result(
        Command::new("git")
            .arg("pull")
            .current_dir(repo_dir)
            .output()
            .map_err(|_| format!("failed to update branch at {:?}/{}", repo_dir, branch_name))?,
        |_| {},
    )
}

/// Checks the status of the [`std::process::Output`] and applies `f` to `stdout` if the process
/// succeedded. If not, builds a readable error containing stdout and stderr.
fn output_to_result<OnSuccessFn, T>(output: Output, f: OnSuccessFn) -> Result<T, String>
where
    OnSuccessFn: Fn(Vec<u8>) -> T,
{
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("stderr: {stderr}\nstdout: {stdout}"))
    } else {
        Ok(f(output.stdout))
    }
}

pub fn check_command_output<F>(output: Output, failure_msg: F)
where
    F: Fn() -> String,
{
    if !output.status.success() {
        if !SUPPRESS_LOGS {
            dbg!(String::from_utf8_lossy(&output.stdout));
            dbg!(String::from_utf8_lossy(&output.stderr));
        }
        panic!("{}", failure_msg());
    }
}

/// Builds the stdout/stderr handler for commands which might output to the terminal.
pub fn build_stdio() -> Stdio {
    if SUPPRESS_LOGS {
        Stdio::null()
    } else {
        Stdio::inherit()
    }
}

pub fn download_file(url: &str, dest_path: &Path) -> Result<(), String> {
    println!("Downloading from {}", url);

    let output = Command::new("curl")
        .arg("-L")
        .arg("-f")
        .arg("-o")
        .arg(dest_path)
        .arg(url)
        .output()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    output_to_result(output, |_| {}).map_err(|e| format!("Failed to download from {}: {}", url, e))
}

pub fn extract_tar_gz(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
    println!("Extracting {:?} to {:?}", archive_path, dest_dir);

    let output = Command::new("tar")
        .arg("-xzf")
        .arg(archive_path)
        .arg("-C")
        .arg(dest_dir)
        .output()
        .map_err(|e| format!("Failed to execute tar: {}", e))?;

    output_to_result(output, |_| {}).map_err(|e| format!("Failed to extract tar.gz: {}", e))
}

pub fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<(), String> {
    println!("Extracting {:?} to {:?}", archive_path, dest_dir);

    let output = Command::new("unzip")
        .arg("-q")
        .arg("-o")
        .arg(archive_path)
        .arg("-d")
        .arg(dest_dir)
        .output()
        .map_err(|e| format!("Failed to execute unzip: {}", e))?;

    output_to_result(output, |_| {}).map_err(|e| format!("Failed to extract zip: {}", e))
}

pub fn make_executable(file_path: &Path) -> Result<(), String> {
    let output = Command::new("chmod")
        .arg("+x")
        .arg(file_path)
        .output()
        .map_err(|e| format!("Failed to execute chmod: {}", e))?;

    output_to_result(output, |_| {}).map_err(|e| format!("Failed to make file executable: {}", e))
}

pub fn download_github_release_asset(
    repo_owner: &str,
    repo_name: &str,
    asset_name_pattern: &str,
    dest_path: &Path,
) -> Result<String, String> {
    println!(
        "Fetching latest release asset matching '{}' for {}/{}",
        asset_name_pattern, repo_owner, repo_name
    );

    let api_url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        repo_owner, repo_name
    );

    let output = Command::new("curl")
        .arg("-sL")
        .arg(&api_url)
        .output()
        .map_err(|e| format!("Failed to execute curl: {}", e))?;

    let json: Value = output_to_result(output, |stdout| {
        serde_json::from_slice(&stdout).map_err(|e| format!("Failed to parse JSON response: {}", e))
    })
    .map_err(|e| format!("Failed to get GitHub API response: {}", e))??;

    let assets = json["assets"]
        .as_array()
        .ok_or_else(|| "No assets array in response".to_string())?;

    let matching_asset = assets
        .iter()
        .find(|asset| {
            asset["name"]
                .as_str()
                .map(|name| name.contains(asset_name_pattern))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            format!(
                "No asset found matching '{}' in latest release",
                asset_name_pattern
            )
        })?;

    let download_url = matching_asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| "Missing browser_download_url in asset".to_string())?
        .to_string();

    download_file(&download_url, dest_path)?;

    Ok(download_url)
}
