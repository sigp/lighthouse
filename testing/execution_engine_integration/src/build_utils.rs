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

pub fn clone_repo(repo_dir: &Path, repo_url: &str) -> bool {
    Command::new("git")
        .arg("clone")
        .arg(repo_url)
        .arg("--recursive")
        .current_dir(repo_dir)
        .output()
        .unwrap_or_else(|_| panic!("failed to clone repo at {}", repo_url))
        .status
        .success()
}

pub fn checkout_branch(repo_dir: &Path, branch_name: &str) -> bool {
    Command::new("git")
        .arg("checkout")
        .arg(branch_name)
        .current_dir(repo_dir)
        .output()
        .unwrap_or_else(|_| {
            panic!(
                "failed to checkout branch at {:?}/{}",
                repo_dir, branch_name,
            )
        })
        .status
        .success()
}

pub fn update_branch(repo_dir: &Path, branch_name: &str) -> bool {
    Command::new("git")
        .arg("pull")
        .current_dir(repo_dir)
        .output()
        .unwrap_or_else(|_| panic!("failed to update branch at {:?}/{}", repo_dir, branch_name))
        .status
        .success()
}

pub fn check_command_output(output: Output, failure_msg: &'static str) {
    if !output.status.success() {
        if !SUPPRESS_LOGS {
            dbg!(String::from_utf8_lossy(&output.stdout));
            dbg!(String::from_utf8_lossy(&output.stderr));
        }
        panic!("{}", failure_msg);
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
