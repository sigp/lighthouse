use crate::SUPPRESS_LOGS;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
