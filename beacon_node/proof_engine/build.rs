#[cfg(feature = "ere-verifier")]
#[path = "build/ere_verifier.rs"]
mod ere_verifier;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/ere_verifier.rs");
    println!("cargo:rerun-if-env-changed=ERE_VERIFIER_CACHE_DIR");

    #[cfg(feature = "ere-verifier")]
    if let Err(error) = ere_verifier::configure() {
        panic!("failed to configure the ERE verifier: {error}");
    }
}
