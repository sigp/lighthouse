fn main() {
    let exit_status = std::process::Command::new("make")
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .status()
        .unwrap();
    assert!(exit_status.success());
}
