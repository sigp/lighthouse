use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const GETH_BRANCH: &str = "merge-kiln";
const GETH_REPO_URL: &str = "https://github.com/MariusVanDerWijden/go-ethereum";

fn main() {
    let manifest_dir: PathBuf = env::var("CARGO_MANIFEST_DIR").unwrap().into();
    let execution_clients_dir = manifest_dir.join("execution_clients");

    if !execution_clients_dir.exists() {
        fs::create_dir(&execution_clients_dir).unwrap();
    }

    build_geth(&execution_clients_dir);
}

fn build_geth(execution_clients_dir: &Path) {
    let repo_dir = execution_clients_dir.join("go-ethereum");

    if !repo_dir.exists() {
        // Clone the repo
        assert!(Command::new("git")
            .arg("clone")
            .arg(GETH_REPO_URL)
            .current_dir(&execution_clients_dir)
            .output()
            .expect("failed to clone geth repo")
            .status
            .success());
    }

    // Checkout the correct branch
    assert!(Command::new("git")
        .arg("checkout")
        .arg(GETH_BRANCH)
        .current_dir(&repo_dir)
        .output()
        .expect("failed to checkout geth branch")
        .status
        .success());

    // Update the branch
    assert!(Command::new("git")
        .arg("pull")
        .current_dir(&repo_dir)
        .output()
        .expect("failed to update geth branch")
        .status
        .success());

    // Build geth
    assert!(Command::new("make")
        .arg("geth")
        .current_dir(&repo_dir)
        .output()
        .expect("failed to make geth")
        .status
        .success());
}
