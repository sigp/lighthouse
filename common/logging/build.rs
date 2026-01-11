//! This build script should only rerun when:
//! 1. This build.rs file is changed.
//! 2. The workspace Cargo.toml changes.
//! 3. Build dependencies change.
use cargo_metadata::MetadataCommand;
use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("Failed to get cargo metadata");

    let workspace_cargo_toml = metadata.workspace_root.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", workspace_cargo_toml);

    let workspace_crates = get_workspace_crates(&metadata);

    // A bit of a hacky way to generate the list of workspace crates and
    // save to a file in OUT_DIR.
    let mut code = String::from("&[\n");
    for crate_name in &workspace_crates {
        code.push_str(&format!("    \"{}\",\n", crate_name));
    }
    code.push_str("]\n");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("workspace_crates.rs");
    fs::write(&dest_path, code).expect("Failed to write workspace_crates.rs");
}

fn get_workspace_crates(metadata: &cargo_metadata::Metadata) -> Vec<String> {
    metadata
        .workspace_members
        .iter()
        .filter_map(|member_id| {
            metadata
                .packages
                .iter()
                .find(|package| &package.id == member_id)
                .map(|package| package.name.clone())
        })
        .collect()
}
