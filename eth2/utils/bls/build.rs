// This build script is symlinked from each project that requires BLS's "fake crypto",
// so that the `fake_crypto` feature of every sub-crate can be turned on by running
// with FAKE_CRYPTO=1 from the top-level workspace.
// At some point in the future it might be possible to do:
// $ cargo test --all --release --features fake_crypto
// but at the present time this doesn't work.
// Related: https://github.com/rust-lang/cargo/issues/5364
fn main() {
    if let Ok(fake_crypto) = std::env::var("FAKE_CRYPTO") {
        if fake_crypto == "1" {
            println!("cargo:rustc-cfg=feature=\"fake_crypto\"");
            println!("cargo:rerun-if-env-changed=FAKE_CRYPTO");
            println!(
                "cargo:warning=[{}]: Compiled with fake BLS cryptography. DO NOT USE, TESTING ONLY",
                std::env::var("CARGO_PKG_NAME").unwrap()
            );
        }
    }
}
