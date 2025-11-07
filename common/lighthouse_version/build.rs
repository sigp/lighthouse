use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const CLIENT_NAME: &str = "Lighthouse";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = Path::new(&manifest_dir);

    // The crate version is inherited from the workspace.
    let semantic_version = env::var("CARGO_PKG_VERSION").unwrap();

    // Hardcode the .git/ path.
    // This assumes the `lighthouse_version` crate will never move.
    let git_dir = manifest_path.join("../../.git");

    if git_dir.exists() {
        // HEAD either contains a commit hash directly (detached HEAD), or a reference to a branch.
        let head_path = git_dir.join("HEAD");
        if head_path.exists() {
            println!("cargo:rerun-if-changed={}", head_path.display());

            if let Ok(head_content) = fs::read_to_string(&head_path) {
                let head_content = head_content.trim();

                // If HEAD is a reference, also check that file.
                if let Some(ref_path) = head_content.strip_prefix("ref: ") {
                    let full_ref_path = git_dir.join(ref_path);
                    if full_ref_path.exists() {
                        println!("cargo:rerun-if-changed={}", full_ref_path.display());
                    }
                }
            }
        }
    }

    // Construct Lighthouse version string without commit hash.
    let base_version = format!("{}/v{}", CLIENT_NAME, semantic_version);

    let commit_hash = get_git_hash(7);
    let commit_prefix = get_git_hash(8);

    // If commit hash is valid, construct the full version string.
    let version = if !commit_hash.is_empty() && commit_hash.len() >= 7 {
        format!("{}-{}", base_version, commit_hash)
    } else {
        base_version
    };

    println!("cargo:rustc-env=GIT_VERSION={}", version);
    println!("cargo:rustc-env=GIT_COMMIT_PREFIX={}", commit_prefix);
    println!("cargo:rustc-env=CLIENT_NAME={}", CLIENT_NAME);
    println!("cargo:rustc-env=SEMANTIC_VERSION={}", semantic_version);
}

fn get_git_hash(len: usize) -> String {
    Command::new("git")
        .args(["rev-parse", &format!("--short={}", len), "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            // Fallback commit prefix for execution engine reporting.
            if len == 8 {
                "00000000".to_string()
            } else {
                String::new()
            }
        })
}
