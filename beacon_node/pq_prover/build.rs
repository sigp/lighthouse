use std::{error::Error, io};

const REVISION_FILE: &str = include_str!("../../leanvm-revision");
const WORKSPACE_MANIFEST: &str = include_str!("../../Cargo.toml");
const WORKSPACE_LOCK: &str = include_str!("../../Cargo.lock");
const UPSTREAM: &str = "https://github.com/leanEthereum/leanVM";

fn main() -> Result<(), Box<dyn Error>> {
    for path in ["leanvm-revision", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed=../../{path}");
    }

    let revision = REVISION_FILE.strip_suffix('\n').unwrap_or(REVISION_FILE);
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            io::Error::other("leanvm-revision must contain a full lowercase Git SHA").into(),
        );
    }

    let manifest_pin = format!("rev = \"{revision}\"");
    let manifest_entries = WORKSPACE_MANIFEST
        .lines()
        .filter(|line| line.contains(UPSTREAM));
    if manifest_entries.clone().count() < 3
        || !manifest_entries
            .into_iter()
            .all(|line| line.contains(&manifest_pin))
    {
        return Err(io::Error::other(
            "leanVM dependencies in Cargo.toml must match leanvm-revision",
        )
        .into());
    }

    let lock_pin = format!("source = \"git+{UPSTREAM}?rev={revision}#{revision}\"");
    let lock_entries = WORKSPACE_LOCK
        .lines()
        .filter(|line| line.starts_with("source = ") && line.contains(UPSTREAM));
    if lock_entries.clone().count() < 3 || !lock_entries.into_iter().all(|line| line == lock_pin) {
        return Err(
            io::Error::other("leanVM sources in Cargo.lock must match leanvm-revision").into(),
        );
    }

    println!("cargo:rustc-env=LIGHTHOUSE_LEANVM_REVISION={revision}");
    Ok(())
}
